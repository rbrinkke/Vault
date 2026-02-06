.PHONY: build install uninstall clean

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
VAULT_ROOT ?= /opt/services/vault

build:
	cargo build --release

install: build
	install -m 0755 target/release/goamet-vault $(BINDIR)/goamet-vault
	@echo "Installed goamet-vault to $(BINDIR)/goamet-vault"

uninstall:
	rm -f $(BINDIR)/goamet-vault
	@echo "Removed goamet-vault from $(BINDIR)/goamet-vault"

setup-user:
	@if ! id svc-vault >/dev/null 2>&1; then \
		useradd --system --no-create-home --shell /usr/sbin/nologin svc-vault; \
		echo "Created system user svc-vault"; \
	else \
		echo "User svc-vault already exists"; \
	fi
	chown root:svc-vault $(VAULT_ROOT)
	chmod 0750 $(VAULT_ROOT)
	chown root:root $(VAULT_ROOT)/credstore
	chmod 0700 $(VAULT_ROOT)/credstore
	@if [ -f $(VAULT_ROOT)/vault.toml ]; then \
		chown root:svc-vault $(VAULT_ROOT)/vault.toml; \
		chmod 0640 $(VAULT_ROOT)/vault.toml; \
	fi
	@if [ -f $(VAULT_ROOT)/audit.log ]; then \
		chown root:svc-vault $(VAULT_ROOT)/audit.log; \
		chmod 0640 $(VAULT_ROOT)/audit.log; \
	fi

install-sudoers:
	install -m 0440 packaging/sudoers.d/svc-vault /etc/sudoers.d/svc-vault
	visudo -c -f /etc/sudoers.d/svc-vault
	@echo "Installed sudoers rules for svc-vault"

clean:
	cargo clean
