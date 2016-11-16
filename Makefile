all: brute
	
CFLAGS += -O2 -Wall
LDLIBS += -lcrypt  -pthread