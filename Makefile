CC	= gcc
CFLAGS	= -Wall -g
PROGS	= traceroute

ALL: $(PROGS)

%: %.c
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean
clean:
	$(RM) $(PROGS)
