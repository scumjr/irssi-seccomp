CFLAGS := -W -Wall -Wextra -I/usr/include/irssi
LDFLAGS := -ldl
TARGET := seccomp.so

ifeq ($(ARM),1)
    CC := /usr/bin/arm-linux-gnueabihf-gcc
    CFLAGS += -I/usr/arm-linux-gnueabihf/include \
	          -I../arm/usr/include/glib-2.0/ \
              -I../arm/usr/lib/arm-linux-gnueabihf/glib-2.0/include/
else
    CFLAGS += $(shell pkg-config glib-2.0 --cflags)
endif

all: $(TARGET)

%.so: %.o
	$(CC) -shared $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -o $@ -c $^

clean:
	rm -f $(TARGET) *.o
