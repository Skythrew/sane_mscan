# Makefile

CC = gcc
CFLAGS = -shared -fPIC
PKG_CONFIG = pkg-config
PKG_NAME = sane-backends
TARGET = libsane-mscan.so.1
SRC = sane_mscan.c
PCFLAGS = $(shell $(PKG_CONFIG) --cflags $(PKG_NAME))
PCLIBS = $(shell $(PKG_CONFIG) --libs $(PKG_NAME))

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(PCFLAGS) -o $@ $^ $(PCLIBS)

clean:
	rm -f $(TARGET)
