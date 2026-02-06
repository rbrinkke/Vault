# Vault prototype (systemd credentials)

Doel: secrets niet in env, alleen tijdelijk in /run/credentials/%N/.
Deze setup is dev; je kunt later dezelfde credstore koppelen aan je echte service.

## Prereq
- systemd 248+
- systemd-creds
- TPM2 optioneel (alleen als je daar voor kiest)

## Gebruik (dev)
1) Maak een encrypted credential:
   /opt/services/vault/scripts/create_cred.sh db_password
   # optioneel: --with-key=tpm2

2) Test via een transient service (geen installatie nodig):
   systemd-run --unit vault-cred-test --wait --collect \
     -p LoadCredentialEncrypted=db_password:/opt/services/vault/credstore/db_password.cred \
     /opt/services/vault/scripts/cred_test.sh db_password

3) Of installeer de test unit:
   cp /opt/services/vault/units/vault-cred-test.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl start vault-cred-test.service

## Multi-service ontwerp
- Alle apps delen 1 credstore in /opt/services/vault/credstore
- Per service een map file in /opt/services/vault/services/<service>.conf
- Genereer een systemd drop-in met /opt/services/vault/scripts/render_dropin.sh
- De drop-in komt in /opt/services/vault/units/<service>.service.d/credentials.conf
- De service-naam mag met of zonder .service (map file gebruikt naam zonder suffix)

### Map file formaat
- Elke regel: CRED_NAME [ENVVAR]
- Als ENVVAR is gezet, wijst die naar /run/credentials/%N/CRED_NAME
- Optioneel: name:path om de cred file locatie te overschrijven

Voorbeeld:
  db_password DB_PASSWORD_FILE
  api_token API_TOKEN_FILE
  #custom_secret:/opt/services/vault/credstore/custom_secret.cred CUSTOM_SECRET_FILE

### Drop-in genereren
  /opt/services/vault/scripts/render_dropin.sh myservice

### Drop-in toepassen (optioneel)
  /opt/services/vault/scripts/render_dropin.sh myservice --apply

## Demo
Zie /opt/services/vault/demo/README.md

## Productie richting
- Voeg LoadCredentialEncrypted toe aan je echte unit.
- Laat je app secrets uit /run/credentials/%N/NAME lezen.
- Zet hardening flags in je unit (NoNewPrivileges, ProtectSystem, ProtectHome, PrivateTmp).
- Auto-start zonder handmatige unlock vereist host key of TPM2.
  YubiKey/phone kan dan niet verplicht bij boot.

## Security samenvatting
- Threat model: beschermt tegen disk/backups, niet tegen root op dezelfde host.
- Access control: `credstore/` 0700, `vault.toml`/`audit.log` 0600, CLI met `umask 077`, alleen root/sudo.
- CLI safety: `get` alleen met expliciete confirmatie, geen secrets naar stdout/logs.
- Audit: alleen metadata, append-only, voorkeur voor hash chaining of journal logging.
- Backups: versleuteld met expliciete key policy en gelogde restore.
- Drop-in hardening: minimaal `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`.
- Operational: rotatie/migratie met verify en rollback (oude cred pas weg na succes).

## Tests
- CLI test suite (126 tests): `sudo /opt/test/vault-test/scripts/test-cli-full.sh` — systemd-integratie + CLI: `sudo /opt/test/vault-test/scripts/run-all-tests.sh`

## Opmerking
- host key encryption beschermt tegen casual exposure/backups, niet tegen root op dezelfde host.
- Als host key nog niet bestaat: systemd-creds setup
