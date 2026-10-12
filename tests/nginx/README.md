# Local Nginx regression gate

This suite runs the repository's actual Nginx template and companion snippets with a real Nginx binary. It requires Python 3, the OpenSSL CLI, and a Nginx build with the HTTP SSL module. There are no Python package dependencies.

```sh
DNSCHECK_NGINX=/absolute/path/to/nginx \
  python3 -m unittest discover -s tests/nginx -p 'test_*.py' -v
```

When `DNSCHECK_NGINX` is unset, the suite searches `PATH` for `nginx`. A missing default binary reports a skip; an explicitly configured missing executable fails. A skipped run does **not** satisfy the proxy gate.

## What is checked

- `nginx -t` parses the actual template, retaining the production template's Unix upstream URL syntax.
- Real HTTPS responses retain HSTS and the other security headers on static pages, shared assets, successful API responses, and error responses.
- Bearer-only GET requests reach the dynamic/challenge APIs, while requests without credentials receive their help pages.
- Named-location routing preserves POST, PUT, DELETE, form bodies, and Authorization headers.
- Every proxy route, including the watcher route, overwrites supplied `X-Addr-Client-IP` headers with the connection's actual client address.
- Diagnostic responses retain `no-store` and the robot policy; only the configured origin receives CORS permission. Both HTTP and HTTPS paths exercise lookalike, subdomain, port, scheme, and missing-origin cases.

## Isolation and limits

The tests create a private temporary directory and a temporary self-signed certificate. HTTPS clients trust that certificate and verify its loopback IP identity. Every network connection goes directly to `127.0.0.1` on an ephemeral, unprivileged port. The upstream deployment names appear only in Host/Origin headers and template strings; they are never resolved or contacted. The client does not follow redirects or use proxy environment variables. No ACME service or external provider is contacted.

Only temporary copies are adapted: filesystem paths point inside the test directory; listener addresses and ports become loopback; and the runtime upstream becomes a local Python echo server. The independent syntax check keeps the Unix upstream syntax and IPv6 listen syntax. Runtime traffic uses IPv4 so an available IPv6 interface or permission to bind a Unix socket is not required. The enclosing test configuration supplies normal HTTP MIME types and private log/temp paths. Repository configuration files are not changed.

Each case gets a new foreground Nginx process and fresh rate-limit state. Startup, requests, configuration checks, and shutdown have deadlines; a watchdog bounds each process lifetime. Cleanup stops the local servers and removes the temporary files. Only synthetic credentials are used, and the backend stub does not log requests.

These are proxy integration tests. The echo server deliberately does not implement application authorization, DNS resolution, WebSocket handshakes, or a real identity provider. Application authentication and watcher behavior have separate Go tests. This gate does not establish a working public delegation, certificate deployment, CDN real-IP configuration, or running service.
