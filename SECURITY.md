# Security Model — goamet-vault

## Threat Model

### In Scope
- **Disk/backup exposure**: Credentials are encrypted at rest via `systemd-creds` (host key and/or TPM2). Stolen disks or unencrypted backups cannot expose secrets.
- **Operator errors**: Policy enforcement, confirmation prompts, and non-interactive mode guard against accidental secret exposure or deletion.
- **Concurrent access**: File locking prevents corruption from parallel CLI invocations.
- **Audit/forensics**: Append-only log with hash chaining ensures tamper detection and accountability.

### Out of Scope
- **Root/kernel compromise**: A root-level attacker on the same host can read host key material and decrypt all credentials. This is inherent to the `systemd-creds` design.
- **Memory-resident secrets**: While we zeroize secrets after use, a privileged process can inspect memory.

## Command Classification

### AI-Allowed (read-only, safe for automated use)
| Command | Description |
|---------|-------------|
| `list` | List credentials (metadata only) |
| `describe` | Show credential metadata |
| `search` | Search by name/description/tags |
| `health` | Run vault health checks |
| `audit log` | View audit trail |
| `audit verify` | Verify audit chain integrity |
| `plan *` | Dry-run preview of any mutating operation |
| `verify *` | Post-operation verification |
| `dropin generate` | Generate drop-in (no install) |
| `dropin diff` | Compare generated vs installed |

### AI-With-Policy (mutating, allowed with `--non-interactive`)
| Command | Requirements |
|---------|-------------|
| `create --non-interactive --from-stdin` | Secret via stdin, policy checks enforced |
| `rotate --non-interactive --auto` | Auto-generated secret, min length enforced |
| `rotate --non-interactive --from-stdin` | Secret via stdin, policy checks enforced |
| `dropin apply` | Installs drop-in + daemon-reload |
| `migrate import` | Encrypts .env secrets into credstore |

### Break-Glass (human only, never automated)
| Command | Reason |
|---------|--------|
| `get --confirm` | Decrypts secret to stdout/file — requires human confirmation and logged reason |
| `delete` | Permanently removes credential — irreversible |

## Access Control

- `credstore/` — `0700 root:root` (only root can read/write encrypted credentials)
- `vault.toml` — `0600 root:root` (metadata: credential names, tags, timestamps)
- `audit.log` — `0600 root:root` (append-only, hash-chained)
- CLI requires root/sudo for all mutating operations
- Read-only commands work with appropriate file permissions

## Audit Guarantees

- Every credential operation is logged with timestamp, actor, action, and result
- Hash chain (SHA-256) links each entry to the previous one
- Canonical JSON serialization ensures deterministic hashing
- `audit verify` detects any tampering or missing entries
- Optional journald forwarding for centralized log collection

## Encryption Key Policy

- Default: `host+tpm2` when TPM2 hardware is available
- Fallback: `host` key only (protects against disk theft, not root)
- Policy option `forbid_host_only_when_tpm2`: reject `--with-key=host` if TPM2 is present
- `health` command audits credentials using weaker-than-available encryption

## Backup and Recovery

- Encrypted credentials are safe to include in backups (encrypted at rest)
- Recovery requires the same host key (`/var/lib/systemd/credential.secret`) or TPM2
- `vault.toml` contains only metadata (no secrets) — safe to back up
- Rotate after restoring from backup to ensure forward secrecy
