# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -fanalyzer -Iinc/generic -Iinc/layers/application -Iinc/layers/data_link -Iinc/layers/network -Iinc/layers/session -Iinc/layers/transport
LDFLAGS := -lpcap

# Source files
SRC_FILES := $(wildcard src/generic/*.c) \
             $(wildcard src/layers/*/*.c)

# Object files
OBJ_FILES := $(addprefix build/,$(notdir $(SRC_FILES:.c=.o)))

# Output binary
TARGET := bin/netstalker

# Rules
all: $(TARGET) docs

rebuild: clean all

$(TARGET): $(OBJ_FILES) | bin
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Pattern rule for building object files
build/%.o: src/generic/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/%.o: src/layers/application/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/%.o: src/layers/data_link/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/%.o: src/layers/network/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@
build/%.o:src/layers/transport/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

# Ensure the output directories exist
bin:
	mkdir -p $@

build:
	mkdir -p $@

docs: Doxyfile
	doxygen Doxyfile

# Clean rule
clean:
	rm -rf build bin docs

.PHONY: all clean
