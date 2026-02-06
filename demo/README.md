# Demo: multi-service credentials met systemd

Deze demo laat zien hoe een service secrets uit /run/credentials/%N/ leest
zonder env-waarden met plaintext secrets.

## 1) Maak demo secrets (interactief)
- /opt/services/vault/scripts/create_cred.sh db_password
- /opt/services/vault/scripts/create_cred.sh api_token

## 2) Genereer drop-in voor de demo service
- /opt/services/vault/scripts/render_dropin.sh vault-demo

Dit maakt:
- /opt/services/vault/units/vault-demo.service.d/credentials.conf

## 3) Installeer de demo unit (optioneel)
- cp /opt/services/vault/units/vault-demo.service /etc/systemd/system/
- /opt/services/vault/scripts/render_dropin.sh vault-demo --apply
- systemctl daemon-reload
- systemctl start vault-demo.service

Output verwacht:
- db_password loaded (N bytes)
- api_token loaded (N bytes)

## 4) Opruimen
- systemctl stop vault-demo.service
- rm /etc/systemd/system/vault-demo.service
- rm -rf /etc/systemd/system/vault-demo.service.d
- systemctl daemon-reload
