CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -g
LDFLAGS ?=
BUILD ?= build
BIN_DIR ?= .
WARNINGS = -Wall -Wextra -Wpedantic
REQUIRED = -std=c17 -D_POSIX_C_SOURCE=200809L -D_FILE_OFFSET_BITS=64 -Iinclude
COMMON = $(BUILD)/protocol.o $(BUILD)/io.o $(BUILD)/path.o
PROGRAMS = $(BIN_DIR)/bserve $(BIN_DIR)/bcurl

.PHONY: all test sanitize capture clean
all: $(PROGRAMS)

$(sort $(BUILD) $(BIN_DIR)):
	mkdir -p $@

$(BUILD)/%.o: src/%.c include/bhttp.h include/io.h include/path.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(REQUIRED) $(CFLAGS) $(WARNINGS) -c $< -o $@

$(BIN_DIR)/bserve: $(BUILD)/bserve.o $(COMMON) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

$(BIN_DIR)/bcurl: $(BUILD)/bcurl.o $(COMMON) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

$(BUILD)/test_protocol: tests/test_protocol.c $(COMMON)
	$(CC) $(CPPFLAGS) $(REQUIRED) $(CFLAGS) $(WARNINGS) $^ $(LDFLAGS) -o $@

$(BUILD)/test_path: tests/test_path.c $(COMMON)
	$(CC) $(CPPFLAGS) $(REQUIRED) $(CFLAGS) $(WARNINGS) $^ $(LDFLAGS) -o $@

test: all $(BUILD)/test_protocol $(BUILD)/test_path
	$(BUILD)/test_protocol
	$(BUILD)/test_path
	BHTTP_BIN_DIR=$(abspath $(BIN_DIR)) python3 -m unittest discover -s tests -p 'test_integration.py' -v

sanitize:
	$(MAKE) BUILD=build/sanitize BIN_DIR=build/sanitize CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie' LDFLAGS='-fsanitize=address,undefined -no-pie' test

capture: all
	BHTTP_BIN_DIR=$(abspath $(BIN_DIR)) python3 tests/capture_exchange.py

clean:
	$(RM) -r build bserve bcurl
