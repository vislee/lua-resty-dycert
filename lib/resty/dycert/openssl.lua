-- Copyright (C) vislee


local bit = require "bit"
local ffi = require "ffi"
local C = ffi.C
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local ffi_cast = ffi.cast
local ffi_str = ffi.string
local ffi_sizeof = ffi.sizeof
local str_fmt = string.format
local tab_concat = table.concat

local NID_commonName = 13
local NID_countryName = 14
local NID_localityName = 15
local NID_stateOrProvinceName = 16
local NID_organizationName = 17
local MBSTRING_UTF8  = 0x1000
local MBSTRING_ASC   = 0x1001
local BIO_CTRL_RESET = 1
local BIO_CTRL_INFO  = 3
local NID_subject_alt_name = 85

local _M = {}


ffi.cdef[[
    typedef long time_t;
    typedef struct bio_st BIO;
    typedef struct bio_method_st BIO_METHOD;
    typedef struct x509_st X509;
    typedef struct evp_pkey_st EVP_PKEY;
    typedef struct X509_req_st X509_REQ;
    typedef struct bignum_st BIGNUM;
    typedef struct asn1_string_st ASN1_INTEGER;
    typedef struct asn1_string_st ASN1_TIME;
    typedef struct X509_name_st X509_NAME;
    typedef struct X509_name_entry_st X509_NAME_ENTRY;
    typedef struct evp_md_st EVP_MD;
    typedef struct evp_cipher_st EVP_CIPHER;
    typedef struct stack_st OPENSSL_STACK;
    typedef struct general_name_st GENERAL_NAME;
    typedef struct asn1_object_st ASN1_OBJECT;
    typedef struct asn1_string_st ASN1_IA5STRING;
    typedef struct asn1_string_st ASN1_STRING;

    unsigned long ERR_peek_last_error(void);
    void ERR_error_string_n(unsigned long e, char *buf, size_t len);
    void ERR_clear_error(void);

    BIO *BIO_new(const BIO_METHOD *type);
    BIO *BIO_new_mem_buf(const void *buf, int len);
    long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
    int BIO_free(BIO *a);
    int i2d_X509_bio(BIO *bp, X509 *x509);
    int i2d_PrivateKey_bio(BIO *bp, const EVP_PKEY *pkey);
    const BIO_METHOD *BIO_s_mem(void);

    typedef int (*pem_password_cb)(char *buf, int size, int rwflag, void *userdata);
    X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
    int PEM_write_bio_X509(BIO *bp, X509 *x);
    EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x,
                                              pem_password_cb *cb, void *u);
    int PEM_write_bio_PrivateKey(BIO *bp, const EVP_PKEY *x, const EVP_CIPHER *enc,
                                     unsigned char *kstr, int klen,
                                     pem_password_cb *cb, void *u);
    X509_REQ *PEM_read_bio_X509_REQ(BIO *bp, X509_REQ **x,
                                            pem_password_cb *cb, void *u);
    X509 *X509_new(void);
    void X509_free(X509 *a);
    int X509_set_version(X509 *x, long version);
    void EVP_PKEY_free(EVP_PKEY *key);
    void X509_REQ_free(X509_REQ *a);
    int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
    int X509_set_subject_name(X509 *x, X509_NAME *name);

    int RAND_bytes(unsigned char *buf, int num);
    int BN_hex2bn(BIGNUM **a, const char *str);
    BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
    void BN_free(BIGNUM *a);
    ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
    void ASN1_INTEGER_free(ASN1_INTEGER *a);

    X509_NAME *X509_get_subject_name(const X509 *x);
    int X509_set_issuer_name(X509 *x, const X509_NAME *name);

    ASN1_TIME *X509_getm_notBefore(const X509 *x);
    ASN1_TIME *X509_getm_notAfter(const X509 *x);
    ASN1_TIME *X509_gmtime_adj(ASN1_TIME *asn1_time, long offset_sec);
    ASN1_TIME *X509_time_adj_ex(ASN1_TIME *asn1_time, int offset_day, long
                                    offset_sec, time_t *in_tm);
    X509_NAME *X509_REQ_get_subject_name(const X509_REQ *req);
    int X509_NAME_get_index_by_NID(const X509_NAME *name, int nid, int lastpos);
    X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc);
    int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type,
                                           const unsigned char *bytes, int len, int loc, int set);
    EVP_PKEY *X509_REQ_get_pubkey(X509_REQ *req);
    int X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
    const EVP_MD *EVP_sha256(void);
    int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);

    ASN1_IA5STRING *ASN1_IA5STRING_new();
    void ASN1_STRING_free(ASN1_STRING *a);
    int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
    GENERAL_NAME* GENERAL_NAME_new(void);
    void GENERAL_NAME_free(GENERAL_NAME* a);
    void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value);
    OPENSSL_STACK* OPENSSL_sk_new_null(void);
    void OPENSSL_sk_push(OPENSSL_STACK* st, const void* val);
    int X509_add1_ext_i2d(X509* x, int nid, OPENSSL_STACK* value, int crit, unsigned long flags);
]]


local c_uchar_type = ffi.typeof("unsigned char[?]")
local bn_ptrptr_ct = ffi.typeof('BIGNUM*[1]')


local errbuf = ffi.new('char[256]')
local function err_fmt(msg)
    local code = C.ERR_peek_last_error()
    C.ERR_error_string_n(code, errbuf, ffi_sizeof(errbuf))
    C.ERR_clear_error()
    return tab_concat({msg, ffi_str(errbuf)}, ", ")
end


function _M.str_to_x509(crt)
    local bio = C.BIO_new_mem_buf(crt, #crt)
    if bio == nil then
        return nil, err_fmt("BIO_new_mem_buf return nil")
    end

    local crt = C.PEM_read_bio_X509(bio, nil, nil, nil)
    if crt == nil then
        C.BIO_free(bio)
        return nil, err_fmt("PEM_read_bio_X509 error")
    end

    C.BIO_free(bio)
    ffi_gc(crt, C.X509_free)

    return crt
end


function _M.str_to_pkey(key)
    local bio = C.BIO_new_mem_buf(key, #key)
    if bio == nil then
        return nil, err_fmt("BIO_new_mem_buf return nil")
    end

    local key = C.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
    if key == nil then
        C.BIO_free(bio)
        return nil, err_fmt("PEM_read_bio_PrivateKey error")
    end

    C.BIO_free(bio)
    ffi_gc(key, C.EVP_PKEY_free)

    return key
end


function _M.str_to_x509req(csr)
    local bio = C.BIO_new_mem_buf(csr, #csr)
    if bio == nil then
        return nil, err_fmt("BIO_new_mem_buf return nil")
    end

    local csr = C.PEM_read_bio_X509_REQ(bio, nil, nil, nil);
    if csr == nil then
        C.BIO_free(bio)
        return nil, err_fmt("PEM_read_bio_X509_REQ error")
    end

    C.BIO_free(bio)
    ffi_gc(csr, C.X509_REQ_free)

    return csr
end


local function wrap_to_x(tox, ...)
    local bio = C.BIO_new(C.BIO_s_mem())
    if bio == nil then
        return nil, err_fmt("BIO_new return nil")
    end

    local r = C.BIO_ctrl(bio, BIO_CTRL_RESET, 0, nil)
    if r ~= 1 then
        return nil, err_fmt("BIO_ctrl return " .. r)
    end

    local r = tox(bio, ...)
    if r ~= 1 then
        return nil, err_fmt("tox return " .. r)
    end

    local buf = ffi_new("char *[1]")
    local len = C.BIO_ctrl(bio, BIO_CTRL_INFO, 0, buf)
    return ffi_str(buf[0], len)
end


function _M.x509_to_pem(x509)
    return wrap_to_x(C.PEM_write_bio_X509, x509)
end


function _M.x509_to_der(x509)
    return wrap_to_x(C.i2d_X509_bio, x509)
end


function _M.pkey_to_pem(pkey)
    return wrap_to_x(C.PEM_write_bio_PrivateKey, pkey, nil, nil, 0, nil, nil)
end


function _M.pkey_to_der(pkey)
    return wrap_to_x(C.i2d_PrivateKey_bio, pkey)
end


local function set_serial_number(crt, hex)
    local bn
    if type(hex) == "string" and #hex > 1 then
        local p = ffi_new(bn_ptrptr_ct)
        if C.BN_hex2bn(p, hex) == 0 then
            return nil, err_fmt("BN_hex2bn return error")
        end

        bn = p[0]
    else
        local buf = c_uchar_type(20)
        local res = C.RAND_bytes(buf, 20)
        if res ~= 1 then
            return nil, err_fmt(str_fmt("RAND_bytes return %d", res))
        end

        local ptr = ffi_cast("char*", buf)
        ptr[0] = bit.band(ptr[0], 0x7f)

        bn = C.BN_bin2bn(buf, 20, nil)
        if bn == nil then
            return nil, err_fmt("BN_bin2bn return nil")
        end
    end
    ffi_gc(bn, C.BN_free)

    local ser = C.BN_to_ASN1_INTEGER(bn, nil)
    ffi_gc(ser, C.ASN1_INTEGER_free)

    if C.X509_set_serialNumber(crt, ser) == 0 then
        return nil, err_fmt("X509_set_serialNumber return error")
    end

    return true
end


local function set_alt_names(crt, names)
    if names == nil or type(names) ~= "table" then
        return false, "invalid names"
    end

    local alt_name_stack = C.OPENSSL_sk_new_null()
    if alt_name_stack == nil then
        return false, err_fmt("OPENSSL_sk_new_null return nil")
    end
    -- local name_free = function(st)
    --     C.OPENSSL_sk_pop_free(st, C.GENERAL_NAME_free)
    -- end
    -- ffi_gc(alt_name_stack, name_free)

    for _, name in ipairs(names) do
        local san = C.GENERAL_NAME_new()
        if san == nil then
            goto continue
        end
        ffi_gc(san, C.GENERAL_NAME_free)

        local ia5 = C.ASN1_IA5STRING_new()
        if ia5 == nil then
            goto continue
        end

        if C.ASN1_STRING_set(ia5, name, #name) ~= 1 then
            C.ASN1_STRING_free(ia5)
            goto continue
        end

        C.GENERAL_NAME_set0_value(san, 2, ia5)
        C.OPENSSL_sk_push(alt_name_stack, san)
::continue::
    end

    local res = C.X509_add1_ext_i2d(crt, NID_subject_alt_name, alt_name_stack, 0, 0x2)
    if res ~= 1 then
        return false, err_fmt("X509_add1_ext_i2d return error")
    end

    return true
end


function _M.gen_signed_cert(csr, ca_key, ca_crt, exts)
    local crt = C.X509_new()
    if crt == nil then
        return nil, err_fmt("X509_new return nil")
    end
    ffi_gc(crt, C.X509_free)

    C.X509_set_version(crt, 0x02)

    set_serial_number(crt, exts["serial"])

    if C.X509_set_issuer_name(crt, C.X509_get_subject_name(ca_crt)) == 0 then
        return nil, err_fmt("X509_set_issuer_name error")
    end

    -- C.X509_gmtime_adj(C.X509_getm_notBefore(crt), 0);
    -- C.X509_gmtime_adj(C.X509_getm_notAfter(crt), 30*24*3600);
    local before = exts["notBefore"] or os.time()
    local after = exts["notAfter"] or before + 30*24*3600
    C.X509_time_adj_ex(C.X509_getm_notBefore(crt), 0, 0, ffi_new("time_t[1]", before))
    C.X509_time_adj_ex(C.X509_getm_notAfter(crt), 0, 0, ffi_new("time_t[1]", after))

    local name = C.X509_REQ_get_subject_name(csr);
    if name == nil then
        return nil, err_fmt("X509_REQ_get_subject_name return nil")
    end

    local cn = exts["commonName"] or exts["CN"] or ""
    local cn_index = C.X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if cn_index >= 0 then
        C.X509_NAME_delete_entry(name, cn_index);
    end
    C.X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn, -1, -1, 0)

    local c = exts["countryName"] or exts["C"] or ""
    local c_index = C.X509_NAME_get_index_by_NID(name, NID_countryName, -1);
    if c_index >= 0 then
        C.X509_NAME_delete_entry(name, c_index);
    end
    C.X509_NAME_add_entry_by_txt(name, "C", MBSTRING_UTF8, c, -1, -1, 0)

    local l = exts["localityName"] or exts["L"] or ""
    local l_index = C.X509_NAME_get_index_by_NID(name, NID_localityName, -1);
    if l_index >= 0 then
        C.X509_NAME_delete_entry(name, l_index);
    end
    C.X509_NAME_add_entry_by_txt(name, "L", MBSTRING_UTF8, l, -1, -1, 0)

    local st = exts["stateOrProvinceName"] or exts["ST"] or ""
    local st_index = C.X509_NAME_get_index_by_NID(name, NID_stateOrProvinceName, -1);
    if st_index >= 0 then
        C.X509_NAME_delete_entry(name, st_index);
    end
    C.X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_UTF8, st, -1, -1, 0)

    local o = exts["organizationName"] or exts["O"] or ""
    local o_index = C.X509_NAME_get_index_by_NID(name, NID_organizationName, -1);
    if o_index >= 0 then
        C.X509_NAME_delete_entry(name, o_index);
    end
    C.X509_NAME_add_entry_by_txt(name, "O", MBSTRING_UTF8, o, -1, -1, 0)

    if C.X509_set_subject_name(crt, name) == 0 then
        return nil, err_fmt("X509_set_subject_name return error")
    end

    set_alt_names(crt, exts["altnames"])

    local pub = C.X509_REQ_get_pubkey(csr)
    if pub == nil then
        return nil, err_fmt("X509_REQ_get_pubkey return nil")
    end

    C.X509_set_pubkey(crt, pub)
    C.EVP_PKEY_free(pub)

    if C.X509_sign(crt, ca_key, C.EVP_sha256()) == 0 then
        return nil, err_fmt("X509_sign return error")
    end

    return crt
end


return _M
