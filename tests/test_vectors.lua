#!/usr/bin/env lua
-- test_vectors.lua - Test suite for IPCrypt implementation

-- Add lib to path
package.path = "../lib/?.lua;../lib/?/init.lua;" .. package.path

local ipcrypt = require("ipcrypt")
local utils = ipcrypt.utils
local ipcrypt_deterministic = ipcrypt.deterministic
local ipcrypt_nd = ipcrypt.nd
local ipcrypt_ndx = ipcrypt.ndx
local kiasu_bc = require("ipcrypt.cipher.kiasu_bc")
local aes_xts = require("ipcrypt.cipher.aes_xts")

-- Test vectors from the specification
local TEST_VECTORS = {
    deterministic = {
        {
            key = "0123456789abcdeffedcba9876543210",
            ip = "0.0.0.0",
            expected = "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb"
        },
        {
            key = "1032547698badcfeefcdab8967452301",
            ip = "255.255.255.255",
            expected = "aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8"
        },
        {
            key = "2b7e151628aed2a6abf7158809cf4f3c",
            ip = "192.0.2.1",
            expected = "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777"
        }
    },
    nd = {
        {
            key = "0123456789abcdeffedcba9876543210",
            ip = "0.0.0.0",
            tweak = "08e0c289bff23b7c",
            expected = "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16"
        },
        {
            key = "1032547698badcfeefcdab8967452301",
            ip = "192.0.2.1",
            tweak = "21bd1834bc088cd2",
            expected = "21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad"
        },
        {
            key = "2b7e151628aed2a6abf7158809cf4f3c",
            ip = "2001:db8::1",
            tweak = "b4ecbe30b70898d7",
            expected = "b4ecbe30b70898d7553ac8974d1b4250eafc4b0aa1f80c96"
        }
    },
    ndx = {
        {
            key = "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
            ip = "0.0.0.0",
            tweak = "21bd1834bc088cd2b4ecbe30b70898d7",
            expected = "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5"
        },
        {
            key = "1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210",
            ip = "192.0.2.1",
            tweak = "08e0c289bff23b7cb4ecbe30b70898d7",
            expected = "08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a"
        },
        {
            key = "2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b",
            ip = "2001:db8::1",
            tweak = "21bd1834bc088cd2b4ecbe30b70898d7",
            expected = "21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4"
        }
    }
}

-- Helper function to compare results
local function assert_equal(actual, expected, test_name)
    if actual ~= expected then
        print("FAILED: " .. test_name)
        print("  Expected: " .. expected)
        print("  Actual:   " .. actual)
        return false
    end
    return true
end

-- Test deterministic mode
local function test_deterministic()
    print("\nTesting ipcrypt-deterministic:")
    local passed = 0
    local failed = 0
    
    for i, test in ipairs(TEST_VECTORS.deterministic) do
        local key = utils.hex_to_bytes(test.key)
        local encrypted = ipcrypt_deterministic.encrypt(test.ip, key)
        
        if assert_equal(encrypted, test.expected,
                       string.format("Test %d: %s", i, test.ip)) then
            -- Also test decryption
            local decrypted = ipcrypt_deterministic.decrypt(encrypted, key)
            if assert_equal(decrypted, test.ip,
                          string.format("Test %d decrypt", i)) then
                passed = passed + 1
                print(string.format("  Test %d: PASSED (%s -> %s)",
                                  i, test.ip, encrypted))
            else
                failed = failed + 1
            end
        else
            failed = failed + 1
        end
    end
    
    print(string.format("Deterministic: %d passed, %d failed", passed, failed))
    return failed == 0
end

-- Test non-deterministic mode with KIASU-BC
local function test_nd()
    print("\nTesting ipcrypt-nd (KIASU-BC):")
    local passed = 0
    local failed = 0
    
    for i, test in ipairs(TEST_VECTORS.nd) do
        local key = utils.hex_to_bytes(test.key)
        local tweak = utils.hex_to_bytes(test.tweak)
        local plaintext = utils.ip_to_bytes(test.ip)
        
        -- Test KIASU-BC directly
        local ciphertext = kiasu_bc.encrypt(key, tweak, plaintext)
        local result = utils.bytes_to_hex(tweak .. ciphertext)
        
        if assert_equal(result, test.expected,
                       string.format("Test %d: %s", i, test.ip)) then
            -- Also test decryption
            local encrypted_data = utils.hex_to_bytes(test.expected)
            local decrypted = ipcrypt_nd.decrypt(encrypted_data, key)
            if assert_equal(decrypted, test.ip,
                          string.format("Test %d decrypt", i)) then
                passed = passed + 1
                print(string.format("  Test %d: PASSED (%s)", i, test.ip))
            else
                failed = failed + 1
            end
        else
            failed = failed + 1
        end
    end
    
    print(string.format("ND: %d passed, %d failed", passed, failed))
    return failed == 0
end

-- Test non-deterministic mode with AES-XTS
local function test_ndx()
    print("\nTesting ipcrypt-ndx (AES-XTS):")
    local passed = 0
    local failed = 0
    
    for i, test in ipairs(TEST_VECTORS.ndx) do
        local key = utils.hex_to_bytes(test.key)
        local tweak = utils.hex_to_bytes(test.tweak)
        local plaintext = utils.ip_to_bytes(test.ip)
        
        -- Test AES-XTS directly
        local ciphertext = aes_xts.encrypt(key, tweak, plaintext)
        local result = utils.bytes_to_hex(tweak .. ciphertext)
        
        if assert_equal(result, test.expected,
                       string.format("Test %d: %s", i, test.ip)) then
            -- Also test decryption
            local encrypted_data = utils.hex_to_bytes(test.expected)
            local decrypted = ipcrypt_ndx.decrypt(encrypted_data, key)
            if assert_equal(decrypted, test.ip,
                          string.format("Test %d decrypt", i)) then
                passed = passed + 1
                print(string.format("  Test %d: PASSED (%s)", i, test.ip))
            else
                failed = failed + 1
            end
        else
            failed = failed + 1
        end
    end
    
    print(string.format("NDX: %d passed, %d failed", passed, failed))
    return failed == 0
end

-- Main test runner
local function main()
    print("==============================================")
    print("IPCrypt Lua Implementation - Test Suite")
    print("==============================================")
    
    local all_passed = true
    
    all_passed = test_deterministic() and all_passed
    all_passed = test_nd() and all_passed
    all_passed = test_ndx() and all_passed
    
    print("\n==============================================")
    if all_passed then
        print("ALL TESTS PASSED!")
    else
        print("SOME TESTS FAILED!")
    end
    print("==============================================")
    
    return all_passed
end

-- Run tests
if arg and arg[0]:match("test_vectors%.lua$") then
    local success = main()
    os.exit(success and 0 or 1)
end

return {
    test_deterministic = test_deterministic,
    test_nd = test_nd,
    test_ndx = test_ndx,
    main = main
}