# Executable name
TARGET = packet_analyzer

# Compiler
CC = gcc

# Compiler flags
# CFLAGS =   -fsanitize=thread -static-libtsan

CFLAGS = -Wall -g3 -Wno-incompatible-pointer-types -fsanitize=address
LDFLAGS = -fsanitize=address

# Libraries
LIBS = -lpcap -lpthread

# Source files
SRCS = main.c queue.c packet_handler.c threads_handler.c connection_tracker.c

# Object files
OBJS = $(SRCS:.c=.o)


all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(TARGET)



re: fclean all


.PHONY: all clean