# Makefile for IPCrypt Lua Implementation

LUA ?= lua
PREFIX ?= /usr/local
LIBDIR = $(PREFIX)/lib/lua/5.4
BINDIR = $(PREFIX)/bin

.PHONY: all test install uninstall clean help

all: help

help:
	@echo "IPCrypt Lua Implementation"
	@echo "=========================="
	@echo ""
	@echo "Available targets:"
	@echo "  test        - Run all tests"
	@echo "  test-quick  - Run quick test suite"
	@echo "  test-random - Test random number generation"
	@echo "  example     - Run example code"
	@echo "  keygen      - Generate a secure key"
	@echo "  install     - Install library and tools"
	@echo "  uninstall   - Remove installed files"
	@echo "  clean       - Clean temporary files"
	@echo ""
	@echo "Usage examples:"
	@echo "  make test"
	@echo "  make install PREFIX=/usr/local"

test:
	@echo "Running test suite..."
	@cd tests && $(LUA) test_vectors.lua
	@cd tests && $(LUA) test_random.lua

test-quick:
	@echo "Running quick tests..."
	@cd tests && $(LUA) test_vectors.lua

test-random:
	@echo "Testing random generation..."
	@cd tests && $(LUA) test_random.lua

example:
	@echo "Running examples..."
	@cd tests && $(LUA) example.lua

keygen:
	@./bin/ipcrypt-keygen

install:
	@echo "Installing IPCrypt Lua library..."
	@mkdir -p $(LIBDIR)/ipcrypt/cipher
	@mkdir -p $(LIBDIR)/ipcrypt/mode
	@mkdir -p $(BINDIR)
	@cp -r lib/ipcrypt/* $(LIBDIR)/ipcrypt/
	@cp bin/ipcrypt-keygen $(BINDIR)/
	@chmod +x $(BINDIR)/ipcrypt-keygen
	@echo "Installed to $(LIBDIR)/ipcrypt"
	@echo "Keygen tool installed to $(BINDIR)/ipcrypt-keygen"

uninstall:
	@echo "Uninstalling IPCrypt Lua library..."
	@rm -rf $(LIBDIR)/ipcrypt
	@rm -f $(BINDIR)/ipcrypt-keygen
	@echo "Uninstalled from $(LIBDIR) and $(BINDIR)"

clean:
	@find . -name "*.luac" -delete
	@find . -name "*~" -delete
	@echo "Cleaned temporary files"