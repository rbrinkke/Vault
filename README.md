# goamet-vault

`goamet-vault` beheert encrypted `.cred` bestanden voor `systemd` credentials. In Rust-services is dit niet de in-process secretlaag: services horen secrets te laden via `service-secrets`, niet via ad hoc `std::env::var` of handmatig lezen uit `/run/credentials/...`.

## Runtime contract
- Productie-secrets komen uit `LoadCredentialEncrypted=` en landen tijdelijk in de per-unit credentials directory.
- De gegenereerde drop-in zet per secret ook `<SECRET>_FILE=%d/<SECRET>`.
- `service-secrets` resolve't in deze volgorde:
  1. `<SECRET>_FILE`
  2. `CREDENTIALS_DIRECTORY/<SECRET>` (`SYSTEMD_CREDENTIALS_DIRECTORY` blijft als compat fallback werken)
  3. plain env alleen buiten productie
- `.env` en `.env.local` mogen blijven voor non-secret config en lokale overrides, niet voor productie-secrets.

## Prereq
- `systemd` 248+
- `systemd-creds`
- TPM2 optioneel

## Gebruik
1. Maak een encrypted credential:
   `/opt/services/vault/scripts/create_cred.sh DATABASE_URL`
2. Test een losse credential via een transient unit:
   `systemd-run --unit vault-cred-test --wait --collect -p LoadCredentialEncrypted=DATABASE_URL:/opt/services/vault/credstore/DATABASE_URL.cred /opt/services/vault/scripts/cred_test.sh DATABASE_URL`
3. Genereer of installeer een service drop-in:
   `/opt/services/vault/scripts/render_dropin.sh auth`
   `/opt/services/vault/scripts/render_dropin.sh auth --apply`

## Service maps
- Elke service krijgt een verplichte base-map in `services/<service>.conf`.
- Elke regel is `SECRET_NAME SECRET_NAME_FILE`.
- Base-maps bevatten alleen verplichte productie-secrets.
- Optionele secrets horen in `services/<service>.optional.conf.example` en worden alleen gebruikt wanneer een host-side overlay-map expliciet wordt meegeleverd. Zo blokkeert een ontbrekende optionele `.cred` de unitstart niet.
- Custom paths blijven mogelijk via `name:path ENVVAR`.

Voorbeeld `services/auth.conf`:
```text
DATABASE_URL DATABASE_URL_FILE
ACTIVITY_DATABASE_URL ACTIVITY_DATABASE_URL_FILE
PRIVATE_KEY_PASSWORD PRIVATE_KEY_PASSWORD_FILE
MFA_ENCRYPTION_KEY MFA_ENCRYPTION_KEY_FILE
PII_ENCRYPTION_KEY PII_ENCRYPTION_KEY_FILE
BLIND_INDEX_KEY BLIND_INDEX_KEY_FILE
SERVICE_TOKEN SERVICE_TOKEN_FILE
```

Bijbehorend optional voorbeeld:
```text
SMTP_PASSWORD SMTP_PASSWORD_FILE
SYNC_ENC_KEY_HEX SYNC_ENC_KEY_HEX_FILE
RUNTIME_KEY_WRAP_KEY RUNTIME_KEY_WRAP_KEY_FILE
```

## Rust services
Een Rust-service hoort secrets via `service-secrets` te laden:

```rust
use service_secrets::{LoadedSecrets, SecretSpec};

const AUTH_SECRET_SPECS: &[SecretSpec] = &[
    SecretSpec::required("DATABASE_URL"),
    SecretSpec::required("SERVICE_TOKEN"),
    SecretSpec::optional("SMTP_PASSWORD"),
];

let app_env = std::env::var("APP_ENV").unwrap_or_else(|_| "development".into());
let secrets = LoadedSecrets::load(AUTH_SECRET_SPECS, &app_env).await?;

let database_url = secrets.require_plain_string("DATABASE_URL").await?;
let service_token = secrets.require_secret_string("SERVICE_TOKEN").await?;
let smtp_password = secrets.optional_secret_string("SMTP_PASSWORD").await?;
```

De unit hoeft dan alleen credentials te leveren; de applicatiecode beslist zelf welke secrets verplicht of optioneel zijn.

## Productie richting
- Gebruik per service een `credentials.conf` drop-in met `LoadCredentialEncrypted=` regels en `%d/<SECRET>`-envverwijzingen.
- Houd `.env` vrij van secrets.
- Standaardiseer op `render_dropin.sh <service> --apply` in deploy-automation zolang dat script al op hosts aanwezig is.
- Voeg hardening flags toe in de unit of override (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`).
- Rotatie blijft restart-gebaseerd: ververs `.cred`, apply de drop-in indien nodig, restart de service.

## Security samenvatting
- Beschermt secrets-at-rest en voorkomt plain env exposure in productie.
- `credstore/` hoort `0700` te zijn; `vault.toml` en `audit.log` `0600`.
- Secrets gaan niet naar stdout of auditlogs.
- Root op dezelfde host blijft out of scope.

## Tests
- Loadergedrag in `service-secrets`: `cargo test --manifest-path /opt/app/vault/service-secrets/Cargo.toml`
- Vault CLI en systemd checks: `cargo test --manifest-path /opt/app/vault/Cargo.toml`
- Production-safe smoke checks: `/opt/services/vault/scripts/smoke-check.sh --root /var/lib/goamet-vault`
