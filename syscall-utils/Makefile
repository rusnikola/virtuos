CC=gcc
LD=gcc
CFLAGS=-Wall -O2 -c
LDFLAGS=
BIN=syscall
PREFIX=/usr/bin
OBJS=syscall.o
HEADERS=syscall.h _syscall.h

.PHONY: clean
.PHONY: install
.PHONY: uninstall

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $< -o $@

$(BIN): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^

uninstall:
	rm -f $(PREFIX)/$(BIN)

install: uninstall $(BIN)
	install -m 0755 $(BIN) $(PREFIX)

clean:
	rm -f *.o $(BIN)
