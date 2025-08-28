#!/usr/bin/env lua
-- test_random.lua - Test cryptographically secure random generation

-- Add lib to path
package.path = "../lib/?.lua;../lib/?/init.lua;" .. package.path

local ipcrypt = require("ipcrypt")
local utils = ipcrypt.utils

print("Testing Random Number Generation")
print("=================================")
print()

-- Check random source
print("Random source: " .. utils.get_random_source())
print("Secure random available: " .. tostring(utils.has_secure_random()))
print()

-- Test random bytes generation
print("Testing random_bytes generation:")
local bytes1 = utils.random_bytes(16)
local bytes2 = utils.random_bytes(16)
print("  16 bytes (hex): " .. utils.bytes_to_hex(bytes1))
print("  16 bytes (hex): " .. utils.bytes_to_hex(bytes2))
print("  Different: " .. tostring(bytes1 ~= bytes2))
print()

-- Test key generation
print("Testing secure key generation:")
if utils.has_secure_random() then
    local key16 = utils.generate_key(16)
    local key32 = utils.generate_key(32)
    print("  16-byte key: " .. utils.bytes_to_hex(key16))
    print("  32-byte key: " .. utils.bytes_to_hex(key32))
else
    print("  Skipped (no secure random available)")
end
print()

-- Test non-deterministic encryption (which uses random_bytes internally)
print("Testing non-deterministic encryption randomness:")
local test_key = utils.hex_to_bytes("0123456789abcdeffedcba9876543210")
local test_ip = "192.168.1.1"

-- Helper function to count table size
local function table_size(t)
    local count = 0
    for _ in pairs(t) do
        count = count + 1
    end
    return count
end

-- Test ipcrypt-nd
print("  ipcrypt-nd (KIASU-BC):")
local nd_results = {}
for i = 1, 5 do
    local encrypted = ipcrypt.nd.encrypt(test_ip, test_key)
    local hex = utils.bytes_to_hex(encrypted)
    nd_results[hex] = true
    print("    Attempt " .. i .. ": " .. hex:sub(1, 16) .. "... (tweak)")
end
print("    Unique results: " .. tostring(table_size(nd_results)) .. "/5")

-- Test ipcrypt-ndx  
print("  ipcrypt-ndx (AES-XTS):")
local test_key32 = utils.hex_to_bytes(
    "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301"
)
local ndx_results = {}
for i = 1, 5 do
    local encrypted = ipcrypt.ndx.encrypt(test_ip, test_key32)
    local hex = utils.bytes_to_hex(encrypted)
    ndx_results[hex] = true
    print("    Attempt " .. i .. ": " .. hex:sub(1, 32) .. "... (tweak)")
end
print("    Unique results: " .. tostring(table_size(ndx_results)) .. "/5")

print()
print("Test complete!")
if utils.has_secure_random() then
    print("✓ Using cryptographically secure random source: " .. utils.get_random_source())
else
    print("✗ ERROR: No secure random source available")
    os.exit(1)
end