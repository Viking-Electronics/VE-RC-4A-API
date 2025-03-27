BIN = rc4a_tester
SRC = relay_test.c
LIB_SRC = network_relay.c
CC ?=gcc
AR ?=ar
CFLAGS ?= -Wall
LIBS=-lssl -lcrypto
LIBARY_NAME=libnetworkrelay.a

all: $(LIBARY_NAME)
	$(CC) $(CFLAGS) -Iinclude  $(SRC) -o $(BIN) -Llib -lnetworkrelay $(LIBS) 

clean:
	rm -rf $(BIN) *.o lib/*.a

lib: $(LIBARY_NAME)
	echo "Lib built"

$(LIBARY_NAME):
	$(CC) $(CFLAGS) -c -Iinclude  $(LIB_SRC) -o networkrelay.o $(LIBS)
	mkdir -p lib
	$(AR) rcs lib/$(LIBARY_NAME) networkrelay.o

.PHONY: lib