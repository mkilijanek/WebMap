# Vendored front-end libraries

Served from this app instead of third-party CDNs (issue #29). Taken from the
npm registry tarballs; the tarball `sha512` matched the registry's
`dist.integrity` when vendored (2026-10-14).

| File | Package | Licence | sha384 of the file |
|---|---|---|---|
| jquery-3.7.1.min.js | jquery@3.7.1 `dist/jquery.min.js` | MIT | `1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs` |
| Chart-2.9.4.min.js | chart.js@2.9.4 `dist/Chart.min.js` | MIT | `zNy6FEbO50N+Cg5wap8IKA4M/ZnLJgzc6w2NqACZaK0u0FXfOWRRJOnQtpZun8ha` |
| clipboard-2.0.11.min.js | clipboard@2.0.11 `dist/clipboard.min.js` | MIT | `J08i8An/QeARD9ExYpvphB8BsyOj3Gh2TSh1aLINKO3L0cMSH2dN3E22zFoXEi0Q` |
| materialize-1.0.0.min.js | materialize-css@1.0.0 `dist/js/materialize.min.js` | MIT | `ZOED+d9HxogEQwD+jFvux96iGQR9TxfJO+mPF2ZS0TuKH6eWrmvPsDpO6I0OWdiX` |
| materialize-1.0.0.min.css | materialize-css@1.0.0 `dist/css/materialize.min.css` | MIT | `5KZdSYqynSzIjQGS2M1O3HW6HVDBjfNx0v5Y2eQuE3vvQ9NTiiPK9/GWc0yYCrgw` |

Check: `openssl dgst -sha384 -binary FILE | base64`
