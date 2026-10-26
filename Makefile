GO ?= go

.PHONY: bootstrap-dev verify m0-01-smoke m0-03-smoke m0-04-smoke m0-05-smoke

bootstrap-dev:
	$(GO) run ./cmd/arc-dev-bootstrap -out .secrets/dev

verify:
	bash scripts/verify-changed.sh

m0-01-smoke:
	bash scripts/test-m0-01.sh

m0-03-smoke:
	bash scripts/test-m0-03.sh

m0-04-smoke:
	bash scripts/test-m0-04.sh

m0-05-smoke:
	bash scripts/test-m0-05.sh

.PHONY: m0-06-smoke m0-06-build m0-06-up
m0-06-smoke:
	bash scripts/test-m0-06.sh

m0-06-build:
	$(GO) build ./cmd/arc-task ./cmd/arc-notify

m0-06-up:
	docker compose -f compose.yaml -f compose.m0-06.yaml --profile m0-06 up --build task notify
