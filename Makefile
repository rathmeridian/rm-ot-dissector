CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
BIN      = otdissect

all: $(BIN)

$(BIN): dissector.c
	$(CC) $(CFLAGS) -o $(BIN) dissector.c

clean:
	rm -f $(BIN)

.PHONY: all clean
