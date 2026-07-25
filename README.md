# certcheck

A small, dependency-free TLS certificate expiry and info checker for
sysadmins and DevOps. It connects to a host over TLS (or reads a local
PEM file), reports the subject, issuer, SANs, validity window and days
until expiry, and exits non-zero when a certificate is expired or about
to expire — handy for monitoring and CI checks.

Runtime uses only the Python standard library (`ssl`, `socket`,
`datetime`, `argparse`). Python 3.9+.

## Install

```sh
pip install -e .
```

This exposes a `certcheck` console command. You can also run it as a
module: `python -m certcheck ...`.

## Usage

### Check a single host

```sh
certcheck check example.com
certcheck check example.com:8443
certcheck check example.com --warn-days 45 --timeout 5
```

Exit status is `0` when the certificate is valid, `1` when it is
expired or expiring within `--warn-days` (default 30), and `2` on an
error (DNS failure, connection refused, unreadable file, invalid
option value).

### Inspect a local PEM file

```sh
certcheck check --file /etc/ssl/certs/mysite.pem
```

### Check many hosts at once

```sh
certcheck batch --file hosts.txt
```

`hosts.txt` has one `HOST[:PORT]` per line; blank lines and lines
starting with `#` are ignored. `batch` exits non-zero if any host is
expiring, expired, or unreachable.

### JSON output

```sh
certcheck check example.com --json
certcheck batch --file hosts.txt --json
```

### Flags

| Flag | Description |
| ---- | ----------- |
| `--warn-days N` | Fail if a cert expires within N days (default 30). Must be >= 0. |
| `--timeout S` | Connection timeout in seconds (default 10). Must be > 0. |
| `--port P` | Default port when none is given in the target (default 443). Must be 1-65535. |
| `--json` | Emit machine-readable JSON. |
| `--insecure` | Skip verification but still read and report the cert (useful for self-signed certs). |

## Example

```sh
$ certcheck check example.com
Target:      example.com:443
Subject CN:  example.com
Issuer CN:   DigiCert TLS RSA SHA256 2020 CA1
SAN:         example.com, www.example.com
Not before:  2021-03-01T00:00:00+00:00
Not after:   2022-03-01T23:59:59+00:00
Days left:   180
Status:      valid
```

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e . -r requirements-dev.txt
python -m pytest -q
```

The pure classification logic lives in `certcheck/core.py` and is fully
unit-tested with no network access. The CLI and socket/SSL I/O live in
`certcheck/cli.py`.

## License

MIT — see [LICENSE](LICENSE).
