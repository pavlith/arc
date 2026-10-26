GO ?= go

.PHONY: bootstrap-dev verify m0-01-smoke m0-03-smoke m0-04-smoke

bootstrap-dev:
	cd sdk && $(GO) run ./cmd/arc-dev-bootstrap -out ../.secrets/dev

verify:
	bash scripts/verify-changed.sh

m0-01-smoke:
	bash scripts/test-m0-01.sh

m0-03-smoke:
	bash scripts/test-m0-03.sh

m0-04-smoke:
	bash scripts/test-m0-04.sh
