-- utils.lua - Utility functions for IPCrypt implementation

local utils = {}

-- Convert a string of bytes to a hex string
function utils.bytes_to_hex(bytes)
    local hex = {}
    for i = 1, #bytes do
        hex[i] = string.format("%02x", string.byte(bytes, i))
    end
    return table.concat(hex)
end

-- Convert a hex string to bytes
function utils.hex_to_bytes(hex)
    local bytes = {}
    hex = hex:gsub("%s", "") -- Remove whitespace
    for i = 1, #hex, 2 do
        bytes[#bytes + 1] = string.char(tonumber(hex:sub(i, i+1), 16))
    end
    return table.concat(bytes)
end

-- XOR two byte strings of equal length
function utils.xor_bytes(a, b)
    assert(#a == #b, "XOR operands must have equal length")
    local result = {}
    for i = 1, #a do
        local byte_a = string.byte(a, i)
        local byte_b = string.byte(b, i)
        result[i] = string.char(bit32 and bit32.bxor(byte_a, byte_b) or (byte_a ~ byte_b))
    end
    return table.concat(result)
end

-- Create a string of zero bytes
function utils.zero_bytes(n)
    return string.rep("\0", n)
end

-- Parse IPv4 address string to 4 bytes
function utils.parse_ipv4(ip_str)
    local octets = {}
    for octet in ip_str:gmatch("(%d+)") do
        local num = tonumber(octet)
        if not num or num > 255 then
            error("Invalid IPv4 address: " .. ip_str)
        end
        octets[#octets + 1] = string.char(num)
    end
    if #octets ~= 4 then
        error("Invalid IPv4 address: " .. ip_str)
    end
    return table.concat(octets)
end

-- Parse IPv6 address string to 16 bytes
function utils.parse_ipv6(ip_str)
    -- Normalize the address by expanding :: 
    local parts = {}
    local left, right = ip_str:match("^(.*)::(.*)$")
    
    if left or right then
        -- Handle :: notation
        left = left or ""
        right = right or ""
        
        local left_parts = {}
        for part in (left .. ":"):gmatch("([^:]*):") do
            if part ~= "" then
                left_parts[#left_parts + 1] = part
            end
        end
        
        local right_parts = {}
        for part in (right .. ":"):gmatch("([^:]*):") do
            if part ~= "" then
                right_parts[#right_parts + 1] = part
            end
        end
        
        -- Fill with zeros
        local zero_count = 8 - #left_parts - #right_parts
        for _, part in ipairs(left_parts) do
            parts[#parts + 1] = part
        end
        for _ = 1, zero_count do
            parts[#parts + 1] = "0"
        end
        for _, part in ipairs(right_parts) do
            parts[#parts + 1] = part
        end
    else
        -- No :: notation
        for part in (ip_str .. ":"):gmatch("([^:]*):") do
            if part ~= "" then
                parts[#parts + 1] = part
            end
        end
    end
    
    if #parts ~= 8 then
        error("Invalid IPv6 address: " .. ip_str)
    end
    
    -- Convert to bytes
    local bytes = {}
    for _, part in ipairs(parts) do
        local num = tonumber(part, 16) or 0
        bytes[#bytes + 1] = string.char(math.floor(num / 256))
        bytes[#bytes + 1] = string.char(num % 256)
    end
    
    return table.concat(bytes)
end

-- Convert IP address string to 16-byte representation
function utils.ip_to_bytes(ip_str)
    if ip_str:match("^%d+%.%d+%.%d+%.%d+$") then
        -- IPv4 address - convert to IPv4-mapped IPv6 format
        local ipv4_bytes = utils.parse_ipv4(ip_str)
        return utils.zero_bytes(10) .. "\xff\xff" .. ipv4_bytes
    else
        -- IPv6 address
        return utils.parse_ipv6(ip_str)
    end
end

-- Convert 16-byte representation back to IP address string
function utils.bytes_to_ip(bytes16)
    assert(#bytes16 == 16, "Input must be 16 bytes")
    
    -- Check for IPv4-mapped IPv6 format
    local prefix = bytes16:sub(1, 10)
    local ffff = bytes16:sub(11, 12)
    
    if prefix == utils.zero_bytes(10) and ffff == "\xff\xff" then
        -- IPv4 address
        local ipv4_bytes = bytes16:sub(13, 16)
        local octets = {}
        for i = 1, 4 do
            octets[i] = string.byte(ipv4_bytes, i)
        end
        return table.concat(octets, ".")
    else
        -- IPv6 address
        local parts = {}
        for i = 1, 16, 2 do
            local high = string.byte(bytes16, i)
            local low = string.byte(bytes16, i + 1)
            parts[#parts + 1] = string.format("%x", high * 256 + low)
        end
        
        -- Try to find the longest sequence of zeros to replace with ::
        local max_start, max_len = 0, 0
        local cur_start, cur_len = 0, 0
        
        for i = 1, 8 do
            if parts[i] == "0" then
                if cur_len == 0 then
                    cur_start = i
                end
                cur_len = cur_len + 1
                if cur_len > max_len then
                    max_start = cur_start
                    max_len = cur_len
                end
            else
                cur_len = 0
            end
        end
        
        -- Build the final string
        if max_len > 1 then
            local result = {}
            for i = 1, max_start - 1 do
                result[#result + 1] = parts[i]
            end
            if max_start == 1 then
                result[#result + 1] = ""
            end
            result[#result + 1] = ""
            for i = max_start + max_len, 8 do
                result[#result + 1] = parts[i]
            end
            return table.concat(result, ":")
        else
            return table.concat(parts, ":")
        end
    end
end

-- Generate random bytes (uses os.time and math.random as fallback)
-- Note: This is NOT cryptographically secure! 
-- For production use, you should use a proper random source
function utils.random_bytes(n)
    math.randomseed(os.time() + os.clock() * 1000000)
    local bytes = {}
    for i = 1, n do
        bytes[i] = string.char(math.random(0, 255))
    end
    return table.concat(bytes)
end

return utils