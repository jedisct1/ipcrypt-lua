-- init.lua - Main module for IPCrypt Lua implementation

local ipcrypt = {
    -- Version information
    VERSION = "1.0.0",

    -- Export individual modules (lazy loaded)
    deterministic = require("ipcrypt.mode.deterministic"),
    nd = require("ipcrypt.mode.nd"),
    ndx = require("ipcrypt.mode.ndx"),
    pfx = require("ipcrypt.mode.pfx"),
    utils = require("ipcrypt.utils"),
}

return ipcrypt