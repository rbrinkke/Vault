# goamet-vault notes

## Wat dit repo wel en niet doet
- `goamet-vault` levert encrypted credentials aan `systemd`.
- Rust-services horen secrets in-process te laden via `/opt/app/vault/service-secrets`, niet via losse `std::env::var` calls of directe file-reads.
- `.env` mag blijven voor non-secret config, maar productie-secrets horen uit `systemd` credentials te komen.

## Canoniek runtime contract
- Gebruik `services/<service>.conf` voor verplichte secrets.
- Gebruik `services/<service>.optional.conf.example` als voorbeeld voor optionele overlays.
- Elke mapregel is `SECRET_NAME SECRET_NAME_FILE`.
- Deploy-scripts genereren een `credentials.conf` drop-in via `/opt/services/vault/scripts/render_dropin.sh <service> --apply`.
- `service-secrets` resolve't `*_FILE` eerst, daarna `CREDENTIALS_DIRECTORY`, en plain env alleen buiten productie.

## Voorbeeld
```text
DATABASE_URL DATABASE_URL_FILE
INTERNAL_SERVICE_JWT_SECRET INTERNAL_SERVICE_JWT_SECRET_FILE
```

De applicatie laadt dan:
```rust
let secrets = LoadedSecrets::load(
    &[
        SecretSpec::required("DATABASE_URL"),
        SecretSpec::required("INTERNAL_SERVICE_JWT_SECRET"),
    ],
    &app_env,
)
.await?;
```

## Operationale regels
- Geen nieuwe production flows via `/run/vault/<service>.env`.
- Geen productie-secrets in `EnvironmentFile`.
- Optionele secrets gaan niet in de base-map; lever die alleen via een expliciete overlay zodat een ontbrekende `.cred` geen startfout veroorzaakt.
- Rotatie is restart-based; auto-refresh is hier geen vereiste.

## Relevante checks
- `cargo test --manifest-path /opt/app/vault/service-secrets/Cargo.toml`
- `cargo test --manifest-path /opt/app/vault/Cargo.toml`
- `sudo /opt/services/vault/scripts/smoke-check.sh --root /var/lib/goamet-vault --with-leak`
