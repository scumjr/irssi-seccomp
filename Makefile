CFLAGS := -W -Wall -Wextra
LDFLAGS := -ldl
TARGET := seccomp.so

ifeq ($(ARM),1)
    CC := /usr/bin/arm-linux-gnueabihf-gcc
    CFLAGS += -I/usr/arm-linux-gnueabihf/include
endif

all: $(TARGET)

%.so: %.o
	$(CC) -shared $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -o $@ -c $^

clean:
	rm -f $(TARGET) *.o
