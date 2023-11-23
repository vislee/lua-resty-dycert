use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

log_level('debug');

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
my $use_luacov = $ENV{'TEST_NGINX_USE_LUACOV'} // '';

no_long_string();

run_tests();

__DATA__


=== TEST 1: dycert
--- http_config
    lua_package_path "./lib/?.lua;./lib/?/init.lua;;";
    variables_hash_max_size 2048;

    init_by_lua_block {
        if "1" == "$use_luacov" then
            require 'luacov.tick'
            jit.off()
        end
        dycert = require("resty.dycert").new()
        local err = dycert:init("t/cert/ca.key", "t/cert/ca.crt", "t/cert/test.key", "t/cert/test.csr")
        if err ~= nil then
            ngx.log(ngx.ERR, "dycert init error ", err)
        end
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name  test.com;

        ssl_certificate_by_lua_block {
            local ngx_ssl = require "ngx.ssl"
            local sni = ngx_ssl.server_name()
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
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        server_tokens off;
        location /foo {
            default_type 'text/plain';
            content_by_lua_block {ngx.status = 201 ngx.say("foo") ngx.exit(201)}
            more_clear_headers Date;
        }
    }
--- config
    server_tokens off;
    lua_ssl_trusted_certificate ../../cert/ca.crt;

    location /t {
        content_by_lua_block {
            do
                local sock = ngx.socket.tcp()

                sock:settimeout(3000)

                local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, "test.com", true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))

                local req = "GET /foo HTTP/1.0\r\nHost: test.com\r\nConnection: close\r\n\r\n"
                local bytes, err = sock:send(req)
                if not bytes then
                    ngx.say("failed to send http request: ", err)
                    return
                end

                ngx.say("sent http request: ", bytes, " bytes.")

                while true do
                    local line, err = sock:receive()
                    if not line then
                        -- ngx.say("failed to receive response status line: ", err)
                        break
                    end

                    ngx.say("received: ", line)
                end

                local ok, err = sock:close()
                ngx.say("close: ", ok, " ", err)
            end  -- do
            -- collectgarbage()
        }
    }

--- request
GET /t
--- response_body
connected: 1
ssl handshake: cdata
sent http request: 56 bytes.
received: HTTP/1.1 201 Created
received: Server: openresty
received: Content-Type: text/plain
received: Content-Length: 4
received: Connection: close
received: 
received: foo
close: 1 nil

--- error_log
lua ssl server name: "test.com"

--- no_error_log
[error]
[alert]


=== TEST 2: dycert with exts
--- http_config
    lua_package_path "./lib/?.lua;./lib/?/init.lua;;";
    variables_hash_max_size 2048;

    init_by_lua_block {
        if "1" == "$use_luacov" then
            require 'luacov.tick'
            jit.off()
        end
        dycert = require("resty.dycert").new()
        local err = dycert:init("t/cert/ca.key", "t/cert/ca.crt", "t/cert/test.key", "t/cert/test.csr")
        if err ~= nil then
            ngx.log(ngx.ERR, "dycert init error ", err)
        end
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        server_name  vislee.com;

        ssl_certificate_by_lua_block {
            local ngx_ssl = require "ngx.ssl"
            local sni = ngx_ssl.server_name()
            local pem, err = dycert:get_cert("PEM", {commonName = sni, countryName = "CN", stateOrProvinceName = "tianjin", notBefore = 1699498000, notAfter = 2000000000, serial = "5B75D3763202B79FD06423A740348BB88A9EB21F", altnames = {sni, "*.vislee.com", "vislee.com"}})
            if err ~= nil then
                ngx.log(ngx.ERR, "failed to get cert: ", err)
                return
            end
            ngx.log(ngx.INFO, pem)

            local cert = ngx_ssl.cert_pem_to_der(pem)
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
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        server_tokens off;
        location /foo {
            default_type 'text/plain';
            content_by_lua_block {ngx.status = 201 ngx.say("foo") ngx.exit(201)}
            more_clear_headers Date;
        }
    }
--- config
    server_tokens off;
    lua_ssl_trusted_certificate ../../cert/ca.crt;

    location /t {
        content_by_lua_block {
            do
                local sock = ngx.socket.tcp()

                sock:settimeout(3000)

                local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake(nil, "vislee.com", true)
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))

                local req = "GET /foo HTTP/1.0\r\nHost: vislee.com\r\nConnection: close\r\n\r\n"
                local bytes, err = sock:send(req)
                if not bytes then
                    ngx.say("failed to send http request: ", err)
                    return
                end

                ngx.say("sent http request: ", bytes, " bytes.")

                while true do
                    local line, err = sock:receive()
                    if not line then
                        -- ngx.say("failed to receive response status line: ", err)
                        break
                    end

                    ngx.say("received: ", line)
                end

                local ok, err = sock:close()
                ngx.say("close: ", ok, " ", err)
            end  -- do
            -- collectgarbage()
        }
    }

--- request
GET /t
--- response_body
connected: 1
ssl handshake: cdata
sent http request: 58 bytes.
received: HTTP/1.1 201 Created
received: Server: openresty
received: Content-Type: text/plain
received: Content-Length: 4
received: Connection: close
received: 
received: foo
close: 1 nil

--- error_log
lua ssl server name: "vislee.com"

--- no_error_log
[error]
[alert]
