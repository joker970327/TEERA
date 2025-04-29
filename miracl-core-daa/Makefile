# 2. miracl core: when you enable DAA feture in makefile or cmakelist, download it and execute follow cmd:
#     2.1 copy c directory in miracl into src, example copy miracl/c ./src/miracl-c
#     2.2 cd ./src/miracl-c;
#     2.3 export CC=gcc CFLAGS=-fPIC; python3 config64.py -o 33;unset CC CFLAGS
#     2.4 cp core.a libcore.a

# Compiler
CC = gcc

CBLS12383_PATH = ../c_bls12383

# Compiler flags
# CFLAGS = -Wall -O2 -I.
CFLAGS = -Wall -O2 -I. -I$(CBLS12383_PATH)

# Linker flags
LDFLAGS = -L$(CBLS12383_PATH) -lcore 

# Source files
SRCS += $(wildcard ./*.c)

# Object files
OBJS = $(SRCS:.c=.o)

# Executable file
TARGET = daa

# Default rule
all: $(TARGET)

# Rule to link object files into an executable
$(TARGET): $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@ 

# Rule to compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule to remove generated files
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean