# lua-resty-dycert
Dynamically generate a certificate based on a CSR and sign it with a CA.

Table of Contents
=================

* [Synopsis](#synopsis)
* [Methods](#methods)
    * [new](#new)
    * [init](#init)
    * [get](#get)
    * [free](#free)
* [Author](#author)
* [Copyright and License](#copyright-and-license)


Synopsis
========

```nginx
http {

    ...

    init_by_lua_block {
        dycert = require("resty.dycert").new("ca.key", "ca.crt", "test.key", "test.csr")
        dycert:init()
    }

    server {
        listen 443 ssl;

        ......

        ssl_certificate_by_lua_block {
            local ssl = require "ngx.ssl"
            local sni = ssl.server_name()
            local cert, err = dycert:get_cert("DER", {commonName = sni})
            if err ~= nil then
                ngx.log(ngx.ERR, "failed to get cert: ", err)
                return
            end
            local pkey, err = dycert:get_pkey("DER")
            if err ~= nil then
                ngx.log(ngx.ERR, "failed to get pkey: ", err)
                return
            end
            ngx_ssl.clear_certs()
            local ok, err = ngx_ssl.set_der_cert(cert)
            if not ok then
                ngx.log(ngx.ERR, "failed to set DER cert: ", err)
                return
            end
            local ok, err = ngx_ssl.set_der_priv_key(pkey)
            if not ok then
                ngx.log(ngx.ERR, "failed to set private key: ", err)
                return
            end
        }

        ......
    }
}
```

[Back to TOC](#table-of-contents)


Methods
=======

new
---
`syntax: dycert = dycert.new(cakey, cacrt, tkey, tcsr)`

Creates a dycert object by `cakey`, `cacrt`, `tkey`, `tcsr`.


init
----
`syntax: err = dycert:init()`

Load the certs. the failures, returns error.


get_cert
--------
`syntax: cert, err = dycert:get_cert(fmt, exts)`

Gets the public key of the dynamic certificate. the failures, returns `nil` and error.

exts is table,

  - exts.commonName: 

  - exts.countryName: 

  - exts.stateOrProvinceName: 

  - exts.notBefore: 

  - exts.notAfter: 


get_pkey
--------
`syntax: pkey, err = dycert:get_pkey(fmt)`

Gets the private key of the dynamic certificate. the failures, returns `nil` and error.


Author
======

wenqiang li(vislee)

[Back to TOC](#table-of-contents)



Copyright and License
=====================

This module is licensed under the GPL-3.0 license.

Copyright (C) 2023-, by vislee.

All rights reserved.

[Back to TOC](#table-of-contents)
