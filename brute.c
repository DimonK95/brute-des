#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>

#define __USE_GNU
#include <crypt.h>

#define MAX_LENGTH (15)
#define SIZE_Q (7)
#define END (2)

typedef enum {
    ST_SUCCESS,
    ST_FAILURE,
} status_t;

typedef enum {
    BM_REC,
    BM_ITER,
} brute_mode_t;

typedef enum {
    TM_SINGLE,
    TM_MULTI,
} thread_mode_t;


typedef char password_t[MAX_LENGTH + 1];

typedef struct config_t {
    brute_mode_t brute_mode;
    thread_mode_t thread_mode;
    char * hash;
    int password_length;
    char * alph;
} config_t;

typedef struct task_t {
    password_t password;
    int from;
    int to;
} task_t;


typedef struct queue_t {
    int tail;
    int head;
    sem_t empty;
    sem_t full;
    pthread_mutex_t head_mutex;
    pthread_mutex_t tail_mutex;
    task_t task[SIZE_Q];
} queue_t;

typedef struct result_t {
    bool found;
    password_t password;
} result_t;

typedef struct context_t {
    config_t * config;
    queue_t queue;
    int alph_size;
    result_t result;
    pthread_cond_t cond; 
    pthread_mutex_t push_mutex;
    pthread_mutex_t event_mutex;
    pthread_mutex_t pop_mutex;
    int tip;
} context_t;

typedef bool (*handler_t) (context_t *, task_t *, struct crypt_data *);

bool queue_init (queue_t * queue) {
    queue -> tail = 0;
    queue -> head = 0;
    int init_head_mutex = pthread_mutex_init (&queue -> head_mutex, NULL);
    int init_tail_mutex = pthread_mutex_init (&queue -> tail_mutex, NULL);
    int init_empty = sem_init(&queue -> empty, 0, SIZE_Q);
    int init_full = sem_init(&queue-> full, 0, 0);
    if (!init_empty && !init_full && !init_head_mutex && !init_tail_mutex) {
        return true;
    }
    if (init_empty)
        sem_destroy(&queue -> empty);
    if (init_full) 
        sem_destroy(&queue -> full);
    if (init_head_mutex)
        pthread_mutex_destroy(&queue -> head_mutex);
    if (init_tail_mutex)
        pthread_mutex_destroy(&queue -> tail_mutex);
    return false;
}
 
void queue_pop (queue_t * queue, task_t * task) {
    
    sem_wait(&queue -> full);
    pthread_mutex_lock(&queue -> head_mutex);

    * task = queue -> task[queue -> head];
     
    if (++queue -> head >= SIZE_Q) 
        queue -> head = 0;
    
    pthread_mutex_unlock(&queue -> head_mutex);
    sem_post(&queue -> empty);
}

void queue_push (queue_t * queue, task_t * task) {
    sem_wait(&queue -> empty);
    pthread_mutex_lock(&queue -> tail_mutex);
    
    queue -> task[queue -> tail] = *task;
    if (++queue -> tail >= SIZE_Q) 
        queue -> tail = 0;
    
    pthread_mutex_unlock(&queue -> tail_mutex);
    sem_post(&queue -> full);
}

bool task_push (context_t * context, task_t * task, struct crypt_data * cd) {
   pthread_mutex_lock(&context -> push_mutex);  
   context -> tip++; 
   pthread_mutex_unlock(&context -> push_mutex); 
   queue_push (&context -> queue, task);
   return context -> result.found;
}


bool check (context_t * context, task_t * task, struct crypt_data * cd){
    //return false;
    // printf("checks %s \n", task -> password);
    // printf("hash %s \n", crypt_r (task -> password, context -> config -> hash, cd));
    if (!strcmp (crypt_r (task -> password, context -> config -> hash, cd), context -> config -> hash)) {
        context -> result.found = true;
        strncpy (context -> result.password, task -> password, sizeof (context -> result.password) - 1);
    } 
    return context -> result.found;
}

bool rec (int pos, context_t * context, handler_t handler, struct crypt_data * cd, task_t * task){
    
    if (pos >= task -> to){ 
        handler (context, task, cd);
        return (context -> result.found);
    }
    int i;
    for (i = 0; i < context -> alph_size; i++){
        task -> password[pos] = context -> config -> alph[i];
        if (rec (pos + 1, context, handler, cd, task)){
            return true;
        }
    }
    return false;
};


bool brute_rec (context_t * context, handler_t handler, struct crypt_data * cd, task_t * task){
    return rec (task->from, context, handler, cd, task);
};

bool brute_iter (context_t * context, handler_t handler, struct crypt_data * cd, task_t * task) {
    int a[context -> config -> password_length];
    int alph_len_1 = context -> alph_size - 1;
    int i;
      
    task -> password[context -> config -> password_length] = 0;
    for (i = task -> from; i < task -> to; i++){
        a[i] = 0;
        task -> password[i] = context -> config -> alph[0];
    }
    
    for (;;) {  
        if (handler(context, task, cd)) break;
        for (i = task -> to - 1; (i >= task -> from) && (a[i] == alph_len_1); i--){
            a[i] = 0;
            task -> password[i] = context -> config -> alph[0];
        }
        if (i < task -> from)
          break;
        task -> password[i] = context -> config -> alph[++a[i]];
    }
    
   
    return context -> result.found;
}


status_t parse_params (int argc, char * argv[], config_t * config)
{
    int option;
    while ((option = getopt(argc, argv, "ira:n:sm")) != -1){
         switch (option){
            case 'i':
              config -> brute_mode = BM_ITER;
              break;
            case 'r':
              config -> brute_mode = BM_REC;
              break;
            case 's':
              config -> thread_mode = TM_SINGLE;
              break;
            case 'm':
              config -> thread_mode = TM_MULTI;
              break;
            case 'a':
              config -> alph = optarg;
              break;
            case 'n':
              config -> password_length = atoi (optarg);
              break;
            default: 
           return ST_FAILURE;
       }
    }
    if (argc > optind + 1) 
        return ST_FAILURE;
    config -> hash = argv[optind];
    return ST_SUCCESS;
}


void brute_all(context_t * context, handler_t handler, struct crypt_data * cd, task_t * task){

    switch (context -> config -> brute_mode)
    {  
        
        case BM_ITER:
          //  printf("BRUTE_ITER\n");
            brute_iter (context, handler, cd, task);
            break;
        case BM_REC:
           // printf("BRUTE_REC\n");
            brute_rec (context, handler, cd, task);
            break;
    }
}

void * worker(void * arg){
    printf("worker\n");
    context_t * context = arg;
    struct crypt_data cd = { .initialized = 0, };
    
    for (;;){
        task_t task;
        queue_pop(&context -> queue, &task);
        task.from = task.to;
        task.to = task.to + END;
        brute_all(context, check, &cd, &task);
        pthread_mutex_lock(&context -> pop_mutex);  
        if (--context -> tip == 0)
            pthread_cond_signal(&context -> cond); 
        pthread_mutex_unlock(&context -> pop_mutex); 
    }
}



void run_single(context_t * context){
    struct crypt_data cd;
    cd.initialized = 0;
    int to;
    for (to = 0; to <= context -> config -> password_length; to++){
        task_t task = { 
            .from = 0,
            .to = to,
        };
        task.password[task.to] = 0;
        brute_all(context, check, &cd, &task);
    }
}


void run_multi(context_t * context){
    int ncpu = 1; (long)sysconf(_SC_NPROCESSORS_ONLN);
    int i;
    for (i = 0; i < ncpu; i++){
        pthread_t thread_a;
        pthread_create (&thread_a, NULL, worker, context); 
        pthread_detach (thread_a);
    }
    
    int to;
    for (to = 0; to <= context -> config -> password_length - END; to++){ 
        struct crypt_data cd;
        cd.initialized = 0;
        task_t task = { 
            .from = 0,
            .to = to,
        };
        task.password[task.to] = 0;
        brute_all(context, task_push, &cd, &task);
    }
    
    pthread_mutex_lock(&context -> event_mutex);
    while (context->tip > 0)
        pthread_cond_wait(&context -> cond, &context -> event_mutex); 
    pthread_mutex_unlock(&context -> event_mutex);
}

    
int main (int argc, char *argv[]) {
    config_t config = {
        .brute_mode = BM_ITER,
        .hash = NULL,
        .alph = "abc",
        .password_length = 4,
        .thread_mode = TM_SINGLE,
    };
    
   
    if (ST_SUCCESS != parse_params (argc, argv, &config)){
        fprintf (stderr, "Parse params error\n");
        return (EXIT_FAILURE);
    }
    
    context_t context = {
       .config = &config,
       .alph_size = strlen (config.alph),
       .result = { .found = false, },
       .tip = 0,
    };
    
    if (!queue_init (&context.queue)){
        fprintf (stderr, "Initialize queue error\n");
        return (EXIT_FAILURE);
    };
    
    if (pthread_mutex_init (&context.pop_mutex, NULL)){
        pthread_mutex_destroy(&context.pop_mutex);
        fprintf (stderr, "Initialize pop_mutex error\n");
        return (EXIT_FAILURE);
    }
    
    if (pthread_mutex_init (&context.push_mutex, NULL)){
        pthread_mutex_destroy(&context.push_mutex);
        fprintf (stderr, "Initialize push_mutex error\n");
        return (EXIT_FAILURE);
    }
    
    if (pthread_mutex_init (&context.event_mutex, NULL)){
        pthread_mutex_destroy(&context.event_mutex);
        fprintf (stderr, "Initialize event_mutex error\n");
        return (EXIT_FAILURE);
    }
    
    if (pthread_cond_init (&context.cond, NULL)){
        pthread_cond_destroy(&context.cond);
        fprintf (stderr, "Initialize cond error\n");
        return (EXIT_FAILURE);
    } 
    printf ("hash = %s\n", config.hash);
    
    

    switch (context.config -> thread_mode)
    {
        case TM_SINGLE:
        {
            run_single(&context);
            break;
        }
        
        case TM_MULTI:
            run_multi(&context);
            break;
    }

    if (context.result.found){
       printf("FOUND\n%s\n", context.result.password);
    }
    else {
        printf("NOT FOUND\n");
    }
    
    return (EXIT_SUCCESS);
}
