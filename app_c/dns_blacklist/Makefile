TARGET := exe

SOURCES := $(wildcard *.c)
OBJECTS := $(patsubst %.c,%.o,$(SOURCES))

CFLAGS := -Os -Wall -Werror -Wextra
LDFLAGS := -lpthread -ljansson

.PHONY: $(TARGET) clean

all: $(TARGET)

$(TARGET):
	gcc -o $(TARGET) $(SOURCES) $(CFLAGS) $(LDFLAGS)

clean:
	rm $(TARGET)
