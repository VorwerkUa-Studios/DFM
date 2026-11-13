CC ?= gcc
CFLAGS ?= -Wall -Wextra -fPIC -O2
LDFLAGS ?= -shared -ldl

TARGET = libstealth.so

all: $(TARGET)

$(TARGET): libstealth.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: all clean
