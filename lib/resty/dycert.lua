-- Copyright (C) vislee
local dyssl = require("resty.dycert.openssl")

local open = io.open
local rawset = rawset
local setmetatable = setmetatable


local _M = {}
local mt = { __index = _M }


function _M.new(ca_key_path, ca_crt_path, key_path, csr_path)
    return setmetatable({
        ca_key_path = ca_key_path,
        ca_crt_path = ca_crt_path,
        key_path = key_path,
        csr_path = csr_path
    }, mt)
end

function _M.init(self)
    local ca_key_fd, err = open(self.ca_key_path, "r")
    if err ~= nil then
        return err
    end
    local ca_key = ca_key_fd:read("*a")
    ca_key_fd:close()

    local ca_crt_fd, err = open(self.ca_crt_path, "r")
    if err ~= nil then
        return err
    end
    local ca_crt = ca_crt_fd:read("*a")
    ca_crt_fd:close()

    local key_fd, err = open(self.key_path, "r")
    if err ~= nil then
        return err
    end
    local key = key_fd:read("*a")
    key_fd:close()

    local csr_fd, err = open(self.csr_path, "r")
    if err ~= nil then
        return err
    end
    local csr = csr_fd:read("*a")
    csr_fd:close()

    local ca_pkey, err = dyssl.str_to_pkey(ca_key)
    if err ~= nil then
        return err
    end

    local ca_x509, err = dyssl.str_to_x509(ca_crt)
    if err ~= nil then
        return err
    end

    local pkey, err = dyssl.str_to_pkey(key)
    if err ~= nil then
        return err
    end

    local xreq, err = dyssl.str_to_x509req(csr)
    if err ~= nil then
        return err
    end

    rawset(self, "ca_pkey", ca_pkey)
    rawset(self, "ca_x509", ca_x509)
    rawset(self, "pkey", pkey)
    rawset(self, "xreq", xreq)

    return nil
end


function _M.get_cert(self, fmt, cn)
    if cn == nil or cn == "" then
        return nil, "Invalid cn"
    end

    if self.ca_pkey == nil or self.ca_x509 == nil or self.xreq == nil then
        return nil, "init failure"
    end

    local x509, err = dyssl.gen_signed_cert(self.xreq, self.ca_pkey, self.ca_x509, cn)
    if err ~= nil then
        return nil, err
    end

    if fmt == "DER" then
        return dyssl.x509_to_der(x509)
    end
    return dyssl.x509_to_pem(x509)
end


function _M.get_pkey(self, fmt)
    if self.pkey == nil then
        return nil, "init failure"
    end

    if fmt == "DER" then
        return dyssl.pkey_to_der(self.pkey)
    end
    return dyssl.pkey_to_pem(self.pkey)
end


return _M
