# Vendored front-end files

Served from this app instead of third-party CDNs (issue #29, v1.2 review
R-04): the Content-Security-Policy only allows `'self'`. Taken from the npm
registry tarballs; the tarball `sha512` matched the registry's
`dist.integrity` when vendored.

## JavaScript and CSS (vendored 2026-10-14)

| File | Package | Licence | sha384 of the file |
|---|---|---|---|
| jquery-3.7.1.min.js | jquery@3.7.1 `dist/jquery.min.js` | MIT | `1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs` |
| Chart-2.9.4.min.js | chart.js@2.9.4 `dist/Chart.min.js` | MIT | `zNy6FEbO50N+Cg5wap8IKA4M/ZnLJgzc6w2NqACZaK0u0FXfOWRRJOnQtpZun8ha` |
| clipboard-2.0.11.min.js | clipboard@2.0.11 `dist/clipboard.min.js` | MIT | `J08i8An/QeARD9ExYpvphB8BsyOj3Gh2TSh1aLINKO3L0cMSH2dN3E22zFoXEi0Q` |
| materialize-1.0.0.min.js | materialize-css@1.0.0 `dist/js/materialize.min.js` | MIT | `ZOED+d9HxogEQwD+jFvux96iGQR9TxfJO+mPF2ZS0TuKH6eWrmvPsDpO6I0OWdiX` |
| materialize-1.0.0.min.css | materialize-css@1.0.0 `dist/css/materialize.min.css` | MIT | `5KZdSYqynSzIjQGS2M1O3HW6HVDBjfNx0v5Y2eQuE3vvQ9NTiiPK9/GWc0yYCrgw` |

## Icon fonts (vendored 2026-10-14, v1.2 review)

| Path | Package | Licence | Notes |
|---|---|---|---|
| fontawesome-free-5.3.1/ | @fortawesome/fontawesome-free@5.3.1 (`css/all.min.css`, `webfonts/*.woff2`, `*.woff`) | Icons CC BY 4.0, fonts SIL OFL 1.1, code MIT (`LICENSE.txt`) | Same version the pages loaded from use.fontawesome.com; `all.min.css` sha384 `mzrmE5qonljUremFsqc01SB46JvROS7bZs3IO2EmfFsd15uHvIt+Y8vEf7N7fWAU`, identical to the CDN file's former SRI hash. EOT/TTF/SVG fonts are not included (only needed by very old browsers). |
| material-icons-1.13.14/ | material-icons@1.13.14 (`iconfont/material-icons.css` first block, `material-icons.woff2`, `.woff`) | Apache-2.0 (`LICENSE`) | Replaces Google Fonts `icon?family=Material+Icons`; only the filled style is used. CSS sha384 `yyIunXUpaSvLkI+M0WwZ4OgmfsEOstzo+jcDR8abwI2xN9CloRB5QXw1Fgm6hc5J` (trimmed file). |

npm tarball integrity at vendoring time:

- `material-icons-1.13.14.tgz`: `sha512-kZOfc7xCC0rAT8Q3DQixYAeT+tBqZnxkseQtp2bxBxz7q5pMAC+wmit7vJn1g/l7wRU+HEPq23gER4iPjGs5Cg==`
- `fontawesome-free-5.3.1.tgz`: `sha512-jt6yi7iZVtkY9Jc6zFo+G2vqL4M81pb3IA3WmnnDt9ci7Asz+mPg4gbZL8pjx0nGFBsG0Bmd7BjU9IQkebqxFA==`

Check a file: `openssl dgst -sha384 -binary FILE | base64`
