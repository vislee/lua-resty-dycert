-- Copyright (C) vislee
local ssl = require("resty.dycert.openssl")

local open = io.open
local setmetatable = setmetatable


local _M = {}
local mt = { __index = _M }


function _M.new(ca_key_path, ca_crt_path, key_path, csr_path)
    local ca_key_fd, err = open(ca_key_path, "r")
    if err ~= nil then
        return nil, err
    end
    local ca_key = ca_key_fd:read("*all")
    ca_key_fd:close()

    local ca_crt_fd, err = open(ca_crt_path, "r")
    if err ~= nil then
        return nil, err
    end
    local ca_crt = ca_crt_fd:read("*all")
    ca_crt_fd:close()

    local key_fd, err = open(key_path, "r")
    if err ~= nil then
        return nil, err
    end
    local key = key_fd:read("*all")
    key_fd:close()

    local csr_fd, err = open(csr_path, "r")
    if err ~= nil then
        return nil, err
    end
    local csr = csr_fd:read("*all")
    csr_fd:close()

    local ca_pkey, err = ssl.str_to_pkey(ca_key)
    if err ~= nil then
        return nil, err
    end

    local ca_x509, err = ssl.str_to_x509(ca_crt)
    if err ~= nil then
        return nil, err
    end

    local pkey, err = ssl.str_to_pkey(key)
    if err ~= nil then
        return nil, err
    end

    local xreq, err = ssl.str_to_x509req(csr)
    if err ~= nil then
        return nil, err
    end

    return setmetatable({
        ca_pkey = ca_pkey,
        ca_x509 = ca_x509,
        pkey = pkey,
        xreq = xreq
    }, mt)
end


function _M.get_cert(self, fmt, cn)
    if cn == nil or cn == "" then
        return nil, "Invalid cn"
    end

    local x509, err = ssl.gen_signed_cert(self.xreq, self.ca_pkey, self.ca_x509, cn)
    if err ~= nil then
        return nil, err
    end

    if fmt == "DER" then
        return ssl.x509_to_der(x509)
    end
    return ssl.x509_to_pem(x509)
end


function _M.get_pkey(self, fmt)
    if fmt == "DER" then
        return ssl.pkey_to_der(self.pkey)
    end
    return ssl.pkey_to_pem(self.pkey)
end


return _M
