TARGET = test
SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))
CC = gcc
CFLAGS = -Wall -I/usr/include -I/usr/local/ilude -L/lib -L/usr/lib -L/usr/local/lib 
LIBS = -lnfnetlink -lnetfilter_queue -lpcre 

$(TARGET):$(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

$(OBJS):$(SRCS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
