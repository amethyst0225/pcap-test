CC = cc
CFLAGS = -Wall -Wextra -Werror
LDFLAGS = -lpcap

SRCS = main.c \
	parse.c

OBJS = $(SRCS:.c=.o)
TARGET = pcap-test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(TARGET)

re: fclean all
