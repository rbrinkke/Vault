# Productie Gap-Analyse — goamet-vault

Datum: 2026-02-06  
Scope: vault software + deployment/runtime (systemd), exclusief wijzigingen aan bestaande productie-units (alle aanbevelingen zijn “wat je zou moeten doen”, niet automatisch toegepast).

## Huidige status (wat er al staat)

- Secrets encrypted at rest via `systemd-creds` (host en/of TPM2 afhankelijk van key-type).
- Guardrails: `--non-interactive`, “break-glass” voor `get --confirm --reason`, `dropin apply` vereist `--confirm`.
- Concurrency: file-locking voorkomt metadata-corruptie bij parallelle runs.
- Audit: append-only log met hash chain + `audit verify` (tamper detectie).
- Diagnostiek: `doctor` en `health`.
- Real-world tests met echte systemd transient units + credentials directory pattern.

## Bewijs (tests die groen zijn)

- CLI full suite: `/opt/test/vault-test/scripts/test-cli-full.sh` (isolated `/tmp/vault-test-*`)  
  Resultaat: 166/166 PASS (laatst gedraaid 2026-02-06).
- Systemd service-achtige tests (transient): `/opt/test/vault-test/scripts/run-all-tests.sh`  
  Resultaat: 6/6 PASS (simple/multi/longrun/env-migration + leak-test).
- Leak test (transient unit, geen `/etc` writes):  
  `sudo /usr/local/bin/goamet-vault test run --runtime-sec 4`  
  Checkt: geen secret in `/proc/<pid>/cmdline`, `ps args`, `journalctl`.

## Must-have vóór productie (blockers)

1. **Scheiding test vs productie data**
   - Observatie: `vault.toml` in `/opt/services/vault` bevat test credentials (`test_*`) en `credstore_path` wijst naar `/opt/services/vault/credstore`.
   - Risico: verwarring, per ongeluk use van test secrets, of test harness dat de “echte” credstore aanraakt.
   - Maatregel:
     - Kies een productie-root (bijv. `/var/lib/goamet-vault`) en migrate/initialiseer daar.
     - Houd `/opt/services/vault` als source repo, niet als productie data root.
   - Acceptatie:
     - `goamet-vault --root /var/lib/goamet-vault doctor` PASS.
     - `vault.toml` bevat geen `test_*` entries in productie-root.

2. **Policy expliciet zetten (default is “allow all”)**
   - Observatie: `vault.toml` heeft momenteel geen `[policy]` sectie; dus `service_allowlist` is leeg (= geen restrictie).
   - Risico: automation kan per ongeluk drop-ins/operaties voor onbedoelde services uitvoeren.
   - Maatregel (minimaal):
     - Definieer `[policy] service_allowlist = ["svc-a", "svc-b", ...]`.
     - Zet `min_auto_secret_length` (bijv. 32 of 48) voor rotaties.
   - Acceptatie:
     - `goamet-vault dropin generate not-allowed` faalt.
     - `goamet-vault plan rotate --auto --length 16 ...` faalt wanneer minimum hoger is.

3. **Key policy voor TPM2 vs host**
   - Observatie: de aanwezige test secrets gebruiken `encryption_key = "host"`.
   - Risico: als TPM2 beschikbaar is maar je draait host-only, verlies je een sterke security boundary (root blijft out-of-scope, maar offline extractie wordt lastiger met TPM2 policy).
   - Maatregel:
     - Als TPM2 beschikbaar is: maak “default” key `host+tpm2` (of `tpm2`) en zet `forbid_host_only_when_tpm2 = true`.
     - Documenteer recovery scenario’s: host key (`/var/lib/systemd/credential.secret`) en TPM2 binding.
   - Acceptatie:
     - `goamet-vault health` geeft warning/fail als host-only gebruikt wordt terwijl TPM2 beschikbaar is.
     - Nieuwe `create/rotate` gebruikt gewenste key policy.

4. **Release/CI: reproduceerbare builds en pinning**
   - Observatie: er staat minstens 1 extra binary op PATH (`/home/rob/.cargo/bin/goamet-vault`) naast `/usr/local/bin/goamet-vault`.
   - Risico: automation gebruikt per ongeluk een andere/oudere binary.
   - Maatregel:
     - Pin expliciet `/usr/local/bin/goamet-vault` in alle automation.
     - Voeg CI toe die:
       - `cargo test` draait
       - `/opt/test/vault-test/scripts/run-all-tests.sh` draait op een runner met systemd (staging VM/CI runner)
       - artifact build + checksum/signature publiceert.
   - Acceptatie:
     - `goamet-vault doctor --path` waarschuwt niet meer, of CI faalt als er meerdere binaries zijn.

## Should-have (sterk aanbevolen)

1. **Audit log operationaliseren**
   - Voeg log-rotatie/retentie toe (audit log groeit onbeperkt).
   - Overweeg `policy.journald_audit = true` met centrale logshipping (metadata-only).
   - Run periodiek `goamet-vault audit verify` en alert op errors.

2. **Back-up en disaster recovery drill**
   - Documenteer en oefen: restore van `credstore/` + `vault.toml` met behoud van decrypt-mogelijkheid (host key/TPM2).
   - Voeg een procedure toe: “na restore: rotate critical secrets”.

3. **Staging parity test**
   - Maak in staging een set services die qua unit-hardening en credential pattern matchen met prod.
   - Gebruik transient tests als baseline, maar test ook echte service start/stop (zonder secrets te loggen).

4. **Test harness isolatie verbeteren**
   - `run-all-tests.sh` gebruikt nu `/opt/services/vault/credstore` als input voor `.cred` files.
   - Aanbevolen: laat de harness zelf een tijdelijke vault root initialiseren en test-credentials genereren (zoals `goamet-vault test run` al doet), zodat de harness nooit op “shared” paths leunt.

## Nice-to-have

- Per-credential ACL’s (niet alleen per-service allowlist).
- Secret versioning/retention (rolling windows, grace periods).
- Automatische rotatie scheduler (met “plan/verify/rollback” workflow en audit reason).
- Extra leak checks: core dumps uit, `coredumpctl` policies, env leakage in child processes, `/proc/<pid>/environ` scanning (root-only, maar relevant voor regressies).

## Conclusie (kort)

- Functioneel en testbaar: de vault en de echte systemd transient tests zijn groen, inclusief leak-detectie.
- Productie-waardigheid hangt nu vooral af van: **scheiding test/prod data**, **expliciete policy**, **key policy (TPM2)**, en **release/CI discipline**.

