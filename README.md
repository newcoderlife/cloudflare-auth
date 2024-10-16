# Cloudflare Auth

Check CF_Authorization in caddy.

## Example

```
(cf-header) {
    @cf_ipv6 {
        header_regexp Cf-Connecting-Ip ^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$
    }

    @cf_jwt_header {
        header Cf-Access-Jwt-Assertion *
    }
}

example.com {
    bind [::]

    handle_path /sub/* {
        cloudflare_auth {
            aud <aud>
        }

        reverse_proxy https://localhost {
            header_up Host sub.example.com
            header_up -CF-Connecting-IP

            transport http {
                tls_server_name sub.example.com
            }
        }
    }

    respond 404
}

sub.example.com {
    import cf-header
    header @cf_jwt_header Set-Cookie "CF_Authorization={http.request.header.Cf-Access-Jwt-Assertion}; Domain=example.com; Path=/sub; HttpOnly; Secure; SameSite=Lax"
    redir @cf_ipv6 https://example.com/sub{uri}

    bind 127.0.0.1 [::1]

    cloudflare_auth {
        aud <aud>
    }

    respond "Hello, world!"
}
```