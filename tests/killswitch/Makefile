CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Wno-unused-function -Wno-unused-variable \
          -I. -I./edk2_includes
TARGET  = test_killswitch
SRC     = test_killswitch.c

all: $(TARGET)
	./$(TARGET)

$(TARGET): $(SRC) edk2_stubs.h ../../src/BootkitPkg/DxeInject/KillSwitch.c
	$(CC) $(CFLAGS) -o $@ $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
