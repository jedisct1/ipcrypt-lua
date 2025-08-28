#!/usr/bin/env lua
-- example.lua - Example usage of IPCrypt Lua implementation

-- Add lib to path
package.path = "../lib/?.lua;../lib/?/init.lua;" .. package.path

local ipcrypt = require("ipcrypt")

print("IPCrypt Lua Implementation - Examples")
print("=====================================\n")

-- Example 1: Deterministic encryption
print("1. Deterministic Encryption (AES-128)")
print("--------------------------------------")
local key16 = ipcrypt.utils.hex_to_bytes("0123456789abcdeffedcba9876543210")
local ip = "192.0.2.1"
print("Original IP: " .. ip)
print("Key: 0123456789abcdeffedcba9876543210")

local encrypted = ipcrypt.deterministic.encrypt(ip, key16)
print("Encrypted: " .. encrypted)

local decrypted = ipcrypt.deterministic.decrypt(encrypted, key16)
print("Decrypted: " .. decrypted)
print()

-- Example 2: Non-deterministic with KIASU-BC
print("2. Non-Deterministic Encryption (KIASU-BC)")
print("------------------------------------------")
local ip2 = "10.0.0.1"
print("Original IP: " .. ip2)

local encrypted_nd = ipcrypt.nd.encrypt(ip2, key16)
print("Encrypted (hex): " .. ipcrypt.utils.bytes_to_hex(encrypted_nd))
print("Length: " .. #encrypted_nd .. " bytes (8-byte tweak + 16-byte ciphertext)")

local decrypted_nd = ipcrypt.nd.decrypt(encrypted_nd, key16)
print("Decrypted: " .. decrypted_nd)
print()

-- Example 3: Non-deterministic with AES-XTS
print("3. Non-Deterministic Encryption (AES-XTS)")
print("-----------------------------------------")
local key32 = ipcrypt.utils.hex_to_bytes(
    "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301"
)
local ip3 = "2001:db8::42"
print("Original IP: " .. ip3)

local encrypted_ndx = ipcrypt.ndx.encrypt(ip3, key32)
print("Encrypted (hex): " .. ipcrypt.utils.bytes_to_hex(encrypted_ndx))
print("Length: " .. #encrypted_ndx .. " bytes (16-byte tweak + 16-byte ciphertext)")

local decrypted_ndx = ipcrypt.ndx.decrypt(encrypted_ndx, key32)
print("Decrypted: " .. decrypted_ndx)
print()

-- Example 4: Multiple encryptions of same IP (showing non-determinism)
print("4. Non-Determinism Demonstration")
print("--------------------------------")
print("Encrypting '8.8.8.8' three times with ipcrypt-nd:")
for i = 1, 3 do
    local enc = ipcrypt.nd.encrypt("8.8.8.8", key16)
    print(string.format("  Attempt %d: %s", i, ipcrypt.utils.bytes_to_hex(enc)))
end
print("Note: Each encryption produces different output due to random tweak")
print()

-- Example 5: IPv4 vs IPv6
print("5. IPv4 and IPv6 Support")
print("------------------------")
local test_ips = {"192.168.1.1", "255.255.255.255", "2001:db8::1", "::1"}
for _, test_ip in ipairs(test_ips) do
    local enc = ipcrypt.deterministic.encrypt(test_ip, key16)
    print(string.format("  %-20s -> %s", test_ip, enc))
end