# Plan: goamet-vault - Rust CLI Password Manager voor GoAmet Services

## Kern beslissing: Wrap systemd-creds, niet vervangen

We bouwen een Rust CLI (`goamet-vault`) die `systemd-creds` wrapt via `std::process::Command`. Geen eigen crypto - systemd-creds doet al AES256-GCM met host key/TPM2. De Rust binary voegt toe wat de bash scripts missen: metadata, rotatie, migratie, audit.

## CLI Commando's

```
goamet-vault <COMMAND>

# Credentials
  create <name>         Maak encrypted credential (--from-stdin, --with-key, --service, --description, --tags)
  get <name>            Decrypt en toon waarde
  list                  Toon alle credentials (--service, --tag, --format table|json)
  delete <name>         Verwijder credential
  rotate <name>         Roteer credential (--from-stdin, --auto, --length)
  describe <name>       Toon metadata
  search <query>        Zoek in namen/beschrijvingen/tags

# Services
  service list           Toon alle service mappings
  service show <name>    Detail van een service
  service add <svc> <cred> --env ENVVAR   Koppel credential aan service

# Drop-in generatie (vervangt render_dropin.sh)
  dropin generate <svc>  Genereer systemd drop-in
  dropin apply <svc>     Genereer + installeer + daemon-reload
  dropin diff <svc>      Toon verschil met huidige

# Migratie (van .env naar credentials)
  migrate scan           Scan alle /etc/opt/services/*.env files
  migrate import <env>   Importeer secrets uit .env (--service, --dry-run)
  migrate verify <svc>   Verifieer service werkt na migratie

# Operationeel
  backup create          Encrypted backup van credstore
  backup restore <path>  Herstel backup
  audit log              Toon audit geschiedenis
  init                   Initialiseer vault (dirs, host key check)
  health                 Check vault gezondheid
```

## Data Model

### Layer 1: Encrypted files (bestaand, ongewijzigd)
`/opt/services/vault/credstore/<name>.cred` - systemd-creds binary format

### Layer 2: Metadata (nieuw)
`/opt/services/vault/vault.toml` - TOML (menselijk leesbaar, < 100 credentials)

```toml
[vault]
version = 1
credstore_path = "/opt/services/vault/credstore"

[[credentials]]
name = "db_password"
description = "PostgreSQL master password"
created_at = "2025-01-03T06:00:00Z"
rotated_at = "2025-01-03T06:00:00Z"
encryption_key = "host"
tags = ["database", "postgresql"]
services = ["auth", "chat-api", "data-sync-v2"]

[[services]]
name = "chat-api"
unit = "chat-api.service"

[[services.credentials]]
name = "db_password"
env_var = "DB_PASSWORD_FILE"
```

### Layer 3: Audit log (nieuw)
`/opt/services/vault/audit.log` - JSONL (append-only)

## Security & Threat Model

### Threat model (expliciet maken)
- Beschermt tegen diefstal van disk/backups en offline toegang.
- Beschermt niet tegen root op dezelfde host of een gecompromitteerde kernel.
- Secrets zijn alleen beschermd zolang de host key/TPM2 veilig is en niet geëxfiltreerd wordt.

### Access control & permissions (policy defaults)
- `credstore/` permissions: `0700` (root:root).
- `vault.toml` en `audit.log`: `0600` (root:root).
- CLI default `umask 077`.
- CLI mag alleen draaien als `root` of via `sudo` met beperkte command allowlist.
- Valideer namen: alleen `[a-zA-Z0-9._-]` en geen `/` of `..` of whitespace.

### CLI safety defaults
- `get` is disabled-by-default in productie, of vereist `--confirm` en `--reason`.
- `get` schrijft nooit naar stdout zonder expliciete opt-in.
- Geen secret values in logs, alleen metadata.

### Audit integriteit
- Audit log is append-only en bevat alleen metadata.
- Voeg hash chaining toe per entry of log naar `journalctl` met beperkte write access.
- Log elke create/delete/rotate/migrate/dropin apply met actor en timestamp.

### Backup key management
- Backups zijn versleuteld met een expliciete key policy.
- Definieer waar de backup key leeft, rotatie-interval, en restore-autoriteit.
- Restore is een apart, gelogd commando met bevestiging.

### Drop-in hardening defaults
- `NoNewPrivileges=yes`
- `ProtectSystem=strict`
- `ProtectHome=read-only`
- `PrivateTmp=yes`
- `ProtectKernelTunables=yes`
- `ProtectKernelModules=yes`
- `ProtectControlGroups=yes`
- `LockPersonality=yes`
- `MemoryDenyWriteExecute=yes`

### Operational procedures (minimaal)
- Rotatie: new secret -> encrypt -> update mapping -> apply drop-in -> restart -> verify -> revoke old.
- Migratie: import -> apply drop-in -> update service config to `_FILE` -> restart -> verify -> remove `.env`.
- Rollback: keep previous credential until service verification passes.

## Project Structuur

```
/opt/services/vault/
  Cargo.toml
  src/
    main.rs                # clap CLI entry point
    lib.rs
    cli/
      mod.rs               # Command enum
      credential.rs        # create, get, list, delete, rotate, describe, search
      service.rs           # service list/show/add
      dropin.rs            # generate, apply, diff
      migrate.rs           # scan, import, verify
      backup.rs            # create, restore
      audit.rs             # log viewer
      init.rs              # vault init
      health.rs            # health check
    core/
      mod.rs
      credstore.rs         # Credential store operaties
      metadata.rs          # TOML metadata read/write
      audit_log.rs         # Append-only audit log
      service_map.rs       # Service mapping operaties
      dropin_gen.rs        # Drop-in generatie (port van render_dropin.sh)
    models/
      mod.rs
      credential.rs        # Credential metadata struct
      service.rs           # Service mapping struct
      vault_config.rs      # Vault config struct
      audit_entry.rs       # Audit entry struct
    util/
      mod.rs
      systemd.rs           # systemd-creds subprocess wrapper
      terminal.rs          # Prompts, kleuren, tabellen
      fs.rs                # File permission helpers
  credstore/               # bestaand
  services/                # bestaand (.conf files, backwards compat)
  units/                   # bestaand
  scripts/                 # bestaand (deprecated na migratie)
```

## Crates

```toml
[dependencies]
clap = { version = "4.4", features = ["derive", "env", "color"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"
chrono = { version = "0.4", features = ["serde"] }
anyhow = "1.0"
thiserror = "2.0"
comfy-table = "7"          # Tabel output
dialoguer = "0.11"         # Interactieve prompts
console = "0.15"           # Kleuren
tempfile = "3"             # Veilige temp files
fs2 = "0.4"                # File locking
rand = "0.8"               # Wachtwoord generatie
glob = "0.3"               # .env file scanning

[profile.release]
lto = true
codegen-units = 1
strip = true
```

Geen crypto crates nodig - systemd-creds doet de encryptie.
Geen async/tokio - synchrone CLI tool.

## Implementatie Fases

### Fase 1: Foundation
**Doel: Binary die create_cred.sh en render_dropin.sh vervangt**
- `Cargo.toml` + project setup
- `src/main.rs` met clap CLI skeleton
- `src/util/systemd.rs` - systemd-creds wrapper (encrypt, decrypt, has_host_key, setup)
- `src/cli/credential.rs` - `create` en `list` commands
- `src/cli/dropin.rs` - `generate` en `apply` commands
- `src/core/dropin_gen.rs` - port van render_dropin.sh logica
- `src/cli/init.rs` - host key check + directory setup
- Test: vergelijk output met bash scripts

### Fase 2: Metadata & Service Management
**Doel: TOML metadata, full CRUD, service mappings**
- `src/core/metadata.rs` - vault.toml read/write
- `src/models/` - alle structs
- `src/cli/credential.rs` uitbreiden: get, delete, describe, search, rotate
- `src/cli/service.rs` - service management
- `src/cli/health.rs` - health check
- `src/util/terminal.rs` - mooie output

### Fase 3: Migratie Tooling
**Doel: Semi-automatische migratie van .env naar credentials**
- `src/cli/migrate.rs` - scan alle 16 .env files in /etc/opt/services/
- Heuristiek voor secret detectie (PASSWORD, SECRET, KEY, TOKEN in variabele naam)
- Import workflow: .env -> systemd-creds encrypt -> vault.toml mapping
- Verify: test of service start met credentials

### Fase 4: Rotatie, Audit, Backup
**Doel: Operationele features**
- `src/core/audit_log.rs` - JSONL append-only log
- `src/cli/audit.rs` - audit log viewer
- `src/cli/backup.rs` - encrypted backup van credstore
- Rotatie workflow: new secret -> re-encrypt -> update services -> reload

### Fase 5: Deploy
**Doel: Productie-ready**
- Release build, deploy naar dev + thin
- Installeer als `/usr/local/bin/goamet-vault`
- Migreer eerste low-risk service (bijv. postcode-api)
- Update CLAUDE.md/README.md
- Deprecate bash scripts

## Kritieke bestanden

### Te porten/vervangen
- `/opt/services/vault/scripts/create_cred.sh` -> `src/util/systemd.rs` + `src/cli/credential.rs`
- `/opt/services/vault/scripts/render_dropin.sh` -> `src/core/dropin_gen.rs`
- `/opt/services/vault/scripts/cred_test.sh` -> `src/cli/health.rs`

### Backwards compatibiliteit
- `/opt/services/vault/services/*.conf` - blijft werken, TOML is de nieuwe bron
- `/opt/services/vault/credstore/*.cred` - ongewijzigd, native systemd-creds format

## Migratie Pad per Service

```
1. goamet-vault migrate scan /etc/opt/services/auth.env
2. goamet-vault migrate import /etc/opt/services/auth.env --service auth
3. goamet-vault dropin generate auth
4. Update service code: lees van _FILE env vars ipv directe env vars
5. goamet-vault dropin apply auth
6. systemctl restart auth && systemctl status auth
7. Verwijder EnvironmentFile= + .env file
```

## Onderzoek: Bestaande Rust Password Managers

Geen geschikt om te forken voor onze use case:
- **ripasso** - PGP-based, pass-compatible, andere encryptie model
- **keyring** - Desktop keyring access, niet server-gericht
- **Vaultify** - Persoonlijke wachtwoorden, niet service secrets
- **rust_keylock** - Eigen encryptie, niet systemd-creds compatible

Onze aanpak (systemd-creds wrappen) is beter omdat:
1. OS-level encryptie (AES256-GCM) met host key/TPM2
2. Native systemd integratie (LoadCredentialEncrypted)
3. Credentials alleen in /run/ tmpfs tijdens runtime
4. Geen eigen crypto code = kleiner aanvalsoppervlak
