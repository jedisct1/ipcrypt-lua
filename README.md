# IPCrypt - Pure Lua Implementation

This is a pure Lua implementation of the IPCrypt specification for IP address encryption and obfuscation.

## Features

- **ipcrypt-deterministic**: Deterministic encryption using AES-128
- **ipcrypt-nd**: Non-deterministic encryption using KIASU-BC with 8-byte tweaks  
- **ipcrypt-ndx**: Non-deterministic encryption using AES-XTS with 16-byte tweaks
- Pure Lua implementation with no external dependencies
- Supports both IPv4 and IPv6 addresses
- Full test suite with specification test vectors

## Requirements

- Lua 5.1+ (with bit32 library) or Lua 5.3+ (with native bitwise operators)

## Usage

### Basic Usage

```lua
local ipcrypt = require("ipcrypt")

-- Generate a key (16 bytes for deterministic/nd, 32 bytes for ndx)
local key16 = ipcrypt.hex_to_bytes("0123456789abcdeffedcba9876543210")
local key32 = ipcrypt.hex_to_bytes("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")

-- Deterministic encryption
local encrypted_ip = ipcrypt.encrypt_deterministic("192.0.2.1", key16)
print(encrypted_ip)  -- IPv6 format string
local decrypted_ip = ipcrypt.decrypt_deterministic(encrypted_ip, key16)
print(decrypted_ip)  -- "192.0.2.1"

-- Non-deterministic encryption with KIASU-BC
local encrypted_data = ipcrypt.encrypt_nd("192.0.2.1", key16)  -- 24 bytes
local decrypted_ip = ipcrypt.decrypt_nd(encrypted_data, key16)
print(decrypted_ip)  -- "192.0.2.1"

-- Non-deterministic encryption with AES-XTS
local encrypted_data = ipcrypt.encrypt_ndx("192.0.2.1", key32)  -- 32 bytes
local decrypted_ip = ipcrypt.decrypt_ndx(encrypted_data, key32)
print(decrypted_ip)  -- "192.0.2.1"
```

### Working with IPv6

```lua
local ipcrypt = require("ipcrypt")

local key = ipcrypt.hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
local ipv6 = "2001:db8::1"

local encrypted = ipcrypt.encrypt_deterministic(ipv6, key)
print(encrypted)  -- Encrypted IPv6 address
local decrypted = ipcrypt.decrypt_deterministic(encrypted, key)
print(decrypted)  -- "2001:db8::1"
```

### Using Custom Tweaks

```lua
local ipcrypt = require("ipcrypt")

local key16 = ipcrypt.hex_to_bytes("0123456789abcdeffedcba9876543210")
local tweak8 = ipcrypt.hex_to_bytes("08e0c289bff23b7c")

-- Encrypt with specific tweak
local encrypted = ipcrypt.encrypt_nd("0.0.0.0", key16, tweak8)
print(ipcrypt.bytes_to_hex(encrypted))
```

## Testing

Run the test suite to verify the implementation:

```bash
lua test_vectors.lua
```

## Module Structure

- `ipcrypt.lua` - Main module interface
- `ipcrypt_deterministic.lua` - Deterministic mode implementation
- `ipcrypt_nd.lua` - Non-deterministic mode with KIASU-BC
- `ipcrypt_ndx.lua` - Non-deterministic mode with AES-XTS
- `aes.lua` - Pure Lua AES-128 implementation
- `kiasu_bc.lua` - KIASU-BC tweakable block cipher
- `aes_xts.lua` - AES-XTS tweakable block cipher
- `utils.lua` - Utility functions for IP conversion and byte operations
- `test_vectors.lua` - Test suite with specification test vectors

## Security Notes

- The random number generation in `utils.random_bytes()` uses `math.random()` which is NOT cryptographically secure
- For production use, replace with a proper CSPRNG or use external random source
- Keys should be generated using a secure random source

## License

This implementation follows the same licensing as the IPCrypt specification.