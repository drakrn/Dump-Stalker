# Variables
CC = gcc
CFLAGS = -Iinc -Wall -Wextra -Werror
LDFLAGS = -lpcap  # Link the libpcap library
SRC_DIR = src
INC_DIR = inc
BUILD_DIR = build
BIN_DIR = bin
SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
TARGET = $(BIN_DIR)/northwind

# Rule to create the build and bin directories if they don't exist
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Default target to build the program
all: $(BIN_DIR) $(TARGET)

# Compile the object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link the object files into the final binary, including libpcap
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Clean temporary files
clean:
	@rm -rf $(BUILD_DIR)
	@echo "Cleaned up build files."

# Clean everything, including the binary
fclean: clean
	@rm -rf $(BIN_DIR)
	@echo "Cleaned up all files, including binary."

# Rebuild the project
re: fclean all

.PHONY: all clean fclean re
