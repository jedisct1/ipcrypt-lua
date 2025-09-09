-- ipcrypt_pfx.lua - Prefix-preserving IPCrypt implementation using AES-128

local utils = require("ipcrypt.utils")
local aes = require("ipcrypt.cipher.aes")

local ipcrypt_pfx = {}

-- Get bit at position from 16-byte array
-- position: 0 = LSB of byte 16, 127 = MSB of byte 1
local function get_bit(data, position)
    local byte_index = 16 - math.floor(position / 8)
    local bit_index = position % 8
    return (string.byte(data, byte_index) >> bit_index) & 1
end

-- Set bit at position in 16-byte array
-- position: 0 = LSB of byte 16, 127 = MSB of byte 1
local function set_bit(data, position, value)
    local byte_index = 16 - math.floor(position / 8)
    local bit_index = position % 8
    local bytes = {string.byte(data, 1, #data)}

    if value == 1 then
        bytes[byte_index] = bytes[byte_index] | (1 << bit_index)
    else
        bytes[byte_index] = bytes[byte_index] & ~(1 << bit_index)
    end

    return string.char(table.unpack(bytes))
end

-- Shift a 16-byte array one bit to the left
local function shift_left_one_bit(data)
    assert(#data == 16, "Input must be 16 bytes")

    local bytes = {string.byte(data, 1, 16)}
    local result = {}
    local carry = 0

    -- Process from least significant byte (byte 16) to most significant (byte 1)
    for i = 16, 1, -1 do
        -- Current byte shifted left by 1, with carry from previous byte
        result[i] = ((bytes[i] << 1) | carry) & 0xFF
        -- Extract the bit that will be carried to the next byte
        carry = (bytes[i] >> 7) & 1
    end

    return string.char(table.unpack(result))
end

-- Pad prefix for prefix_len_bits=0 (IPv6)
local function pad_prefix_0()
    -- Set bit at position 0 (LSB of byte 16)
    return string.rep("\0", 15) .. "\1"
end

-- Pad prefix for prefix_len_bits=96 (IPv4)
local function pad_prefix_96()
    -- For IPv4, the result is always the same since they all have
    -- the same IPv4-mapped prefix (00...00 ffff)
    return "\0\0\0\1" .. string.rep("\0", 10) .. "\255\255"
end

-- Check if an IP is IPv4
local function is_ipv4(ip_bytes)
    -- Check for IPv4-mapped IPv6 format
    return ip_bytes:sub(1, 10) == string.rep("\0", 10) and ip_bytes:sub(11, 12) == "\255\255"
end

-- Encrypt an IP address using ipcrypt-pfx
function ipcrypt_pfx.encrypt(ip_str, key)
    assert(#key == 32, "Key must be 32 bytes")

    -- Split the key into two AES-128 keys
    local K1 = key:sub(1, 16)
    local K2 = key:sub(17, 32)

    -- Check that K1 and K2 are different
    assert(K1 ~= K2, "The two halves of the key must be different")

    -- Convert IP to 16-byte representation
    local bytes16 = utils.ip_to_bytes(ip_str)

    -- Initialize encrypted result with zeros
    local encrypted = string.rep("\0", 16)

    -- Determine starting point
    local ipv4 = is_ipv4(bytes16)
    local prefix_start = ipv4 and 96 or 0

    -- If IPv4, copy the IPv4-mapped prefix
    if ipv4 then
        encrypted = bytes16:sub(1, 12) .. encrypted:sub(13, 16)
    end

    -- Initialize padded_prefix for the starting prefix length
    local padded_prefix
    if ipv4 then
        padded_prefix = pad_prefix_96()
    else
        padded_prefix = pad_prefix_0()
    end

    -- Process each bit position
    for prefix_len_bits = prefix_start, 127 do
        -- Compute pseudorandom function with dual AES encryption
        local e1 = aes.encrypt(padded_prefix, K1)
        local e2 = aes.encrypt(padded_prefix, K2)

        -- XOR the two encryptions
        local e = {}
        for i = 1, 16 do
            e[i] = string.byte(e1, i) ~ string.byte(e2, i)
        end

        -- We only need the least significant bit of byte 16
        local cipher_bit = e[16] & 1

        -- Extract the current bit from the original IP
        local current_bit_pos = 127 - prefix_len_bits

        -- Get the original bit and XOR with cipher bit
        local original_bit = get_bit(bytes16, current_bit_pos)
        local encrypted_bit = cipher_bit ~ original_bit

        -- Set the bit in the encrypted result
        encrypted = set_bit(encrypted, current_bit_pos, encrypted_bit)

        -- Prepare padded_prefix for next iteration
        -- Shift left by 1 bit and insert the next bit from bytes16
        padded_prefix = shift_left_one_bit(padded_prefix)
        padded_prefix = set_bit(padded_prefix, 0, original_bit)
    end

    -- Convert back to IP address
    return utils.bytes_to_ip(encrypted)
end

-- Decrypt an IP address using ipcrypt-pfx
function ipcrypt_pfx.decrypt(encrypted_ip_str, key)
    assert(#key == 32, "Key must be 32 bytes")

    -- Split the key into two AES-128 keys
    local K1 = key:sub(1, 16)
    local K2 = key:sub(17, 32)

    -- Check that K1 and K2 are different
    assert(K1 ~= K2, "The two halves of the key must be different")

    -- Convert encrypted IP to 16-byte representation
    local encrypted_bytes = utils.ip_to_bytes(encrypted_ip_str)

    -- Initialize decrypted result
    local decrypted = string.rep("\0", 16)

    -- For decryption, we need to determine if this was originally IPv4
    local ipv4 = is_ipv4(encrypted_bytes)
    local prefix_start = ipv4 and 96 or 0

    -- If this was originally IPv4, set up the IPv4-mapped IPv6 prefix
    if ipv4 then
        decrypted = string.rep("\0", 10) .. "\255\255" .. decrypted:sub(13, 16)
    end

    -- Initialize padded_prefix for the starting prefix length
    local padded_prefix
    if prefix_start == 0 then
        padded_prefix = pad_prefix_0()
    else
        padded_prefix = pad_prefix_96()
    end

    -- Process each bit position
    for prefix_len_bits = prefix_start, 127 do
        -- Compute pseudorandom function with dual AES encryption
        local e1 = aes.encrypt(padded_prefix, K1)
        local e2 = aes.encrypt(padded_prefix, K2)

        -- XOR the two encryptions
        local e = {}
        for i = 1, 16 do
            e[i] = string.byte(e1, i) ~ string.byte(e2, i)
        end

        -- We only need the least significant bit of byte 16
        local cipher_bit = e[16] & 1

        -- Extract the current bit from the encrypted IP
        local current_bit_pos = 127 - prefix_len_bits

        -- Get the encrypted bit and XOR with cipher bit to recover original
        local encrypted_bit = get_bit(encrypted_bytes, current_bit_pos)
        local original_bit = cipher_bit ~ encrypted_bit

        -- Set the bit in the decrypted result
        decrypted = set_bit(decrypted, current_bit_pos, original_bit)

        -- Prepare padded_prefix for next iteration
        -- Shift left by 1 bit and insert the recovered bit
        padded_prefix = shift_left_one_bit(padded_prefix)
        padded_prefix = set_bit(padded_prefix, 0, original_bit)
    end

    -- Convert back to IP address
    return utils.bytes_to_ip(decrypted)
end

return ipcrypt_pfx