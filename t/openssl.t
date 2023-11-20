use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

log_level('debug');

my $use_luacov = $ENV{'TEST_NGINX_USE_LUACOV'} // '';

my $pwd = cwd();
our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
    variables_hash_max_size 2048;
    init_by_lua_block {
        if "1" == "$use_luacov" then
            require 'luacov.tick'
            jit.off()
        end
    }
};

no_long_string();

run_tests();

__DATA__

=== TEST 1: Load CA pem
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local ssl = require("resty.dycert.openssl")

            local x509, err = ssl.str_to_x509(io.open("t/cert/ca.crt"):read("*a"))
            if err ~= nil then
                ngx.log(ngx.ERR, "str_to_x509", err)
                ngx.print(err)
                return
            end

            ngx.print(ssl.x509_to_pem(x509))
        }
    }
--- request
    GET /t
--- response_body eval
"-----BEGIN CERTIFICATE-----
MIIF1jCCA76gAwIBAgIUFqGSaXkRBpzqAWQ3OB7NlOVePkgwDQYJKoZIhvcNAQEL
BQAwfDELMAkGA1UEBhMCQ04xCzAJBgNVBAgMAkJKMQswCQYDVQQHDAJCSjELMAkG
A1UECgwCY2ExCzAJBgNVBAsMAmNhMRQwEgYDVQQDDAt3d3cuY2EudGVzdDEjMCEG
CSqGSIb3DQEJARYUbG91aXZpc2xlZUBnbWFpbC5jb20wHhcNMjMxMTAxMDYwMTM0
WhcNMzMxMDI5MDYwMTM0WjB8MQswCQYDVQQGEwJDTjELMAkGA1UECAwCQkoxCzAJ
BgNVBAcMAkJKMQswCQYDVQQKDAJjYTELMAkGA1UECwwCY2ExFDASBgNVBAMMC3d3
dy5jYS50ZXN0MSMwIQYJKoZIhvcNAQkBFhRsb3VpdmlzbGVlQGdtYWlsLmNvbTCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALFWp+4Ca8kdfkmWILxkc8L7
/q3j03kUSzhGuGp2mn+wxvUVmGTGAHLHiQZj6XakjKahiVcXiadKrmYONtnOeqx0
oK3apQBzS9i1EREAVho/VZ41SrGQ6qKH2/cqA0OK0lWcdVXD0Sz2RzpTMw4TaoCN
S7vTd+4WZHSVax89DcStA9AxF8idPStOSpOlUFomjEFhhf9n2Qr20y8YQITbztam
744EkRFw7bwzWhCmDrPanSGskl2y0R0Tii5by2AxaayOAH8vlFz5cW/Yd7PnQdl7
3v/c6ybTcwfLJGqyiyhhnLlzu7HOUFyrmHZRchGO0+TayKkmBgDW+88qxr0rjbmS
wa0KnH2OZ1w0rhUrLwa/QwScNIuNgsdSTbQLN/5hlJroKG6aViZV6cn4eGwuWdqY
IVxUKMj8DFALX+ajC52/JLoQn+9uTqdDg1OddcvO55DmOLp4s+jDwCdEj/bYpP0f
uBJz3qa+4PovY1MSQdoMtJWYWHYtnzJ/SnkWRErTttTdpku8EKZEA4o9bghGltgk
yNWzIONtzrhJCtqfSegKhgo/g2f06s4WrfWYw6DnP0o7w+PWeDdVEtRUCmaX7xHn
KXGOgnu88F8uMZuDa4m+vR6K8Tg6Vg1px9upjyv+sscTTIgXdWscXXAO94UIjFY3
XWcDoFXqNOAQB1zBkF0TAgMBAAGjUDBOMB0GA1UdDgQWBBQhF/MD8pBaFnYCqQ7L
ZGHNVokn5jAfBgNVHSMEGDAWgBQhF/MD8pBaFnYCqQ7LZGHNVokn5jAMBgNVHRME
BTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQA3INbMtQNZHxOiAkUWuua5dLY1U6mg
A00WhLyGpKbTnkFAhLagoSO5r1qoEDYb17jwaNpFJKgOAEZ4KJh5qCGYdi6vkE5l
30+Q7QOGN9wUJ1Z0h5gAo7cU0NW535Cl8fYAsD8wAc5pcwb/DGfAE3PTW19T+528
1Jhz5qQDR/nHQilKEI3AY+ukbmeR15P1gkqBmigXwW643wHVsSVLQqRMDMcpRUJM
HnxOTLA57QTfnG1FeVEMtdHt9n37zOop+cH2UbgoAd+c/poHPNwT5OVX4nnpI+PV
cKUg/PpwtxsMT0cXepUH5aa7FdQlXjmX7FwLagI/uHzlKED1jpR0Jh865Ht1jqIa
hC3siTQ3IYBuN3303LcWU+SLKsG2e8JSfejRYuNuiGA37tFNwk8T17YeymgK8ZBZ
pdmE3fVHy85oYaACEZLo3i4LhpRSltq83kF9s3tr/pi73hLgW5HTP+0JJBAuVT4a
STyApW/u9u+16Mh0pu1BSQivZm67NJ+zLHgNN+dZSSrje9m2V5cQhg8/0Rk70DUS
pIg7aMik2VhAzCsxxyVoR4zhGr6UBMvafJA8G+KtFJ9NX+wTjJG6EfjB8HZjXg9L
MWpA1TcJxJJapNVLZiZfnLvzh8+dlG8VAQLc4UYRooSpa2n5P61Ke8C/wnjUpamm
/K0tGpaLERZdvQ==
-----END CERTIFICATE-----
"
--- no_error_log
[error]


=== TEST 2: Load CA Pkey
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local ssl = require("resty.dycert.openssl")

            local pkey, err = ssl.str_to_pkey(io.open("t/cert/ca.key"):read("*a"))
            if err ~= nil then
                ngx.log(ngx.ERR, "str_to_pkey", err)
                ngx.print(err)
                return
            end

            ngx.print(ssl.pkey_to_pem(pkey))
        }
    }
--- request
    GET /t
--- response_body eval
"-----BEGIN PRIVATE KEY-----
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
8br6Pv89YnjgDuug9LKVGWI2kVBxSg==
-----END PRIVATE KEY-----
"
--- no_error_log
[error]



