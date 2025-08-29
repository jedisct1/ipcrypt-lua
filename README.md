# IPCrypt - Pure Lua Implementation

A pure Lua implementation of the IPCrypt specification for IP address encryption and obfuscation.

## Features

- **Deterministic encryption** - AES-128 based, always produces same output for same input
- **Non-deterministic (ND)** - KIASU-BC with 8-byte random tweaks  
- **Non-deterministic extended (NDX)** - AES-XTS with 16-byte random tweaks
- **IPv4 and IPv6 support** - Full support for both address families
- **Zero dependencies** - Pure Lua implementation

## Requirements

- **Lua 5.3++** - Native bitwise operators required
- **Unix-like OS** - /dev/urandom or /dev/random required for secure random

## Installation

### Quick Start

```bash
# Run tests
make test

# Generate a secure key

make keygen

# Run examples

make example
```

### System Installation

```bash
# Install to system (default: /usr/local)
sudo make install

# Custom prefix
sudo make install PREFIX=/opt/local

# Uninstall
sudo make uninstall
```

### LuaRocks Installation

```bash
luarocks install ipcrypt-1.0.1-1.rockspec
```

## Usage

### Basic Usage

```lua
local ipcrypt = require("ipcrypt")

-- Generate secure keys
local key16 = ipcrypt.utils.generate_key(16)  -- For deterministic/ND
local key32 = ipcrypt.utils.generate_key(32)  -- For NDX

-- Deterministic encryption (same input = same output)
local encrypted = ipcrypt.deterministic.encrypt("192.0.2.1", key16)
print(encrypted)  -- IPv6 format: "fa71:fba4:8e6c:205e:3805:2dae:3fba:39f1"

local decrypted = ipcrypt.deterministic.decrypt(encrypted, key16)
print(decrypted)  -- "192.0.2.1"
```

### Non-Deterministic Modes

```lua
-- ND mode with KIASU-BC (8-byte tweak)
local encrypted_nd = ipcrypt.nd.encrypt("10.0.0.1", key16)
-- Returns 24 bytes: 8-byte tweak + 16-byte ciphertext

local decrypted_nd = ipcrypt.nd.decrypt(encrypted_nd, key16)
print(decrypted_nd)  -- "10.0.0.1"

-- NDX mode with AES-XTS (16-byte tweak)
local encrypted_ndx = ipcrypt.ndx.encrypt("2001:db8::1", key32)
-- Returns 32 bytes: 16-byte tweak + 16-byte ciphertext

local decrypted_ndx = ipcrypt.ndx.decrypt(encrypted_ndx, key32)
print(decrypted_ndx)  -- "2001:db8::1"
```

### Key Generation

```bash
# Command-line tool
./bin/ipcrypt-keygen              # Generate 16-byte key
./bin/ipcrypt-keygen -l 32        # Generate 32-byte key
./bin/ipcrypt-keygen -n 5         # Generate 5 keys
./bin/ipcrypt-keygen --check      # Check random source
```

```lua
-- Programmatic key generation
local utils = require("ipcrypt.utils")

-- Generate keys (fails if no secure random available)
local key16 = utils.generate_key(16)
local key32 = utils.generate_key(32)

-- Get hex representation
local hex_key = utils.generate_key_hex(16)
print(hex_key)  -- "a1b2c3d4..."

-- Check security
if utils.has_secure_random() then
    print("Secure random available: " .. utils.get_random_source())
end
```

## API Reference

### Main Module (`ipcrypt`)

- `ipcrypt.VERSION` - Library version string
- `ipcrypt.deterministic` - Deterministic mode module
- `ipcrypt.nd` - Non-deterministic mode (KIASU-BC)
- `ipcrypt.ndx` - Non-deterministic extended mode (AES-XTS)
- `ipcrypt.utils` - Utility functions

### Deterministic Mode (`ipcrypt.deterministic`)

- `encrypt(ip_string, key16)` - Encrypt IP address deterministically
- `decrypt(encrypted_ip, key16)` - Decrypt to original IP

### ND Mode (`ipcrypt.nd`)

- `encrypt(ip_string, key16, [tweak8])` - Encrypt with optional tweak
- `decrypt(encrypted_bytes, key16)` - Decrypt (tweak included in data)

### NDX Mode (`ipcrypt.ndx`)

- `encrypt(ip_string, key32, [tweak16])` - Encrypt with optional tweak
- `decrypt(encrypted_bytes, key32)` - Decrypt (tweak included in data)

### Utils (`ipcrypt.utils`)

- `generate_key(length)` - Generate secure key (16 or 32 bytes)
- `generate_key_hex(length)` - Generate key as hex string
- `has_secure_random()` - Check if secure random available
- `get_random_source()` - Get random source name
- `random_bytes(n)` - Generate n random bytes
- `hex_to_bytes(hex)` - Convert hex string to bytes
- `bytes_to_hex(bytes)` - Convert bytes to hex string
- `ip_to_bytes(ip_string)` - Convert IP to 16-byte format
- `bytes_to_ip(bytes16)` - Convert 16 bytes to IP string

## Testing

```bash
# Run all tests
make test

# Run specific tests
cd tests
lua test_vectors.lua
lua test_random.lua

# Run test suite with colored output
./run-tests.sh
```

## Troubleshooting

### No secure random source

- Ensure /dev/urandom exists (standard on Linux/macOS/BSD)
- Check file permissions
- For Windows, use WSL or consider alternative implementations

### Module not found errors

- Check Lua version: `lua -v` (must be 5.3+)
- Verify installation paths
- Use proper require paths or package.path configuration
