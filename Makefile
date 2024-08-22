# Executable name
TARGET = packet_analyzer

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -g

# Libraries
LIBS = -lpcap -lpthread

# Source files
SRCS = main.c queue.c

# Object files
OBJS = $(SRCS:.c=.o)


all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(TARGET)


.PHONY: all clean