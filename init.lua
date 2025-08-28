-- init.lua - Package loader for IPCrypt
-- This file allows using the library from the project root

-- Add lib directory to package path
package.path = "./lib/?.lua;./lib/?/init.lua;" .. package.path

-- Return the main module
return require("ipcrypt")