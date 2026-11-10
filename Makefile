GO ?= go

.PHONY: test-bootstrap verify m0-01-smoke m0-02-smoke m0-03-smoke m0-04-smoke m0-05-smoke m0-06-smoke runtime-smoke

test-bootstrap:
	$(GO) run ./test/bootstrap -out .secrets/dev

verify:
	bash scripts/verify-changed.sh

m0-01-smoke:
	bash scripts/test-m0-01.sh

m0-02-smoke:
	bash scripts/test-m0-02.sh

m0-03-smoke:
	bash scripts/test-m0-03.sh

m0-04-smoke:
	bash scripts/test-m0-04.sh

m0-05-smoke:
	bash scripts/test-m0-05.sh

m0-06-smoke:
	bash scripts/test-m0-06.sh

runtime-smoke:
	python3 scripts/test-runtime.py
