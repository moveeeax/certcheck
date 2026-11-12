# certcheck

A small, dependency-free TLS certificate expiry and info checker for
sysadmins and DevOps. It connects to a host over TLS (or reads a local
PEM file), reports the subject, issuer, SANs, validity window and days
until expiry, and exits non-zero when a certificate is expired, about
to expire or not trusted — handy for monitoring and CI checks. It can
also survey chains, protocol versions and cipher suites across a host
list, and check TLS secrets and cert-manager Certificates in a
Kubernetes cluster.

Runtime uses only the Python standard library (`ssl`, `socket`,
`datetime`, `argparse`). Python 3.11+. The `k8s` command also needs
`kubectl` on `PATH`.

## Install

```sh
pip install git+https://github.com/moveeeax/certcheck.git
```

To pin a version, append `@<tag-or-commit>` to the URL. From a
local clone, `pip install .` (or `pip install -e .` for development).

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
expired, expiring within `--warn-days` (default 30) or fails
verification, and `2` on an error (DNS failure, connection refused,
unreadable file, invalid option value).

When verification fails, certcheck reconnects without verification,
reads the certificate anyway and reports it with its dates. `status`
is then `expired` or `not_yet_valid` when the dates explain the
failure, `hostname_mismatch` when the certificate does not cover the
host, and `untrusted` otherwise (self-signed, unknown issuer, missing
intermediate). The OpenSSL reason is printed as `Verify:` and returned
as `verify_error` in JSON. `--insecure` skips verification entirely,
so trust problems are not reported and do not fail the check. Use
`--ca-file` to verify against a private CA instead.

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

### Survey chains, protocols and ciphers

```sh
certcheck inventory --file hosts.txt --min-version tls1.2 --concurrency 20
certcheck inventory --file hosts.txt --ciphers --require-forward-secrecy --json
```

For every host in the list (same format as `batch`), `inventory` runs
the `check` logic and adds:

- the presented chain, leaf first, with expiry and status of each
  certificate;
- findings: `self_signed`, `hostname_mismatch`, `incomplete_chain`
  (the issuer was neither sent nor trusted), `untrusted`,
  `chain_expired` / `chain_expiring` for intermediates, `protocol`
  for each accepted version older than `--min-version` (default
  `tls1.2`), and with `--require-forward-secrecy`, `forward_secrecy`
  for each accepted suite without it;
- `protocols`: one handshake per TLS 1.0 to 1.3, each `true`
  (accepted), `false` (refused) or `null` (this machine's OpenSSL
  cannot offer that version, so it was not tested);
- with `--ciphers`, the accepted suites, each with a
  `forward_secrecy` flag. TLS 1.2-and-older suites are tried one per
  handshake; Python cannot restrict TLS 1.3 suites, so for TLS 1.3
  only the suite the server picks is listed.

Hosts are surveyed `--concurrency` at a time (default 10) and reported
in input order. Exit status is `1` if any host has a breach or a
finding, or could not be reached.

### Kubernetes TLS secrets and cert-manager Certificates

```sh
certcheck k8s -A --warn-days 30
certcheck k8s -n ingress --exclude-issuer 'istio-*' --json
```

`k8s` reads every `kubernetes.io/tls` secret through `kubectl` and
reports the leaf certificate of `tls.crt`, sorted by days left (rows
with no usable expiry first). When cert-manager is installed, each
`Certificate` is matched to its secret by `spec.secretName` and its
Ready condition, issuer and `renewalTime` are added. A Certificate
that is not Ready marks its row `not_ready` and fails the check; one
whose secret does not exist gets a row of its own.

It uses kubectl's current context and credentials and only runs
`get` and `api-resources`, so read access to secrets is required.
Exit status is `0` when all rows are valid, `1` on any expiring,
expired, not-ready or unreadable entry, and `2` when kubectl fails.

| Flag | Description |
| ---- | ----------- |
| `-n`, `--namespace NS` | Namespace to check (default: kubectl's current one). |
| `-A`, `--all-namespaces` | Check every namespace. |
| `-l`, `--selector SEL` | Label selector for secrets. Certificates whose secret is filtered out are not reported. |
| `--exclude-namespace GLOB` | Skip namespaces matching GLOB. Repeatable. |
| `--exclude-issuer GLOB` | Skip certificates whose issuer CN or cert-manager issuer name matches GLOB. Repeatable. |
| `--context`, `--kubeconfig` | Passed to kubectl. |
| `--kubectl PATH` | kubectl binary (default `kubectl`). |
| `--warn-days N`, `--timeout S`, `--json` | As for `check`; `--timeout` becomes kubectl's `--request-timeout`. |

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
| `--insecure` | Skip verification but still read and report the cert. Trust failures are not reported. |
| `--ca-file PATH` | Verify against this PEM CA bundle instead of the system trust store. |

`check`, `batch` and `inventory` take these flags; `inventory` also
takes `--min-version`, `--ciphers`, `--require-forward-secrecy` and
`--concurrency`.

## Example

Illustrative output, run on 2026-11-04 (days left are whole days from now
until `Not after`):

```sh
$ certcheck check example.com
Target:      example.com:443
Subject CN:  example.com
Issuer CN:   DigiCert TLS RSA SHA256 2020 CA1
SAN:         example.com, www.example.com
Not before:  2026-01-15T00:00:00+00:00
Not after:   2027-01-15T23:59:59+00:00
Days left:   72
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
`certcheck/cli.py`, the `inventory` probes in `certcheck/inventory.py`
and the kubectl calls in `certcheck/k8s.py`. Tests use local TLS
servers on 127.0.0.1 and a fake kubectl, so no cluster or internet
access is needed.

## License

MIT — see [LICENSE](LICENSE).
