# Kapkan — root orchestrator.
#   engine/   the Go binary (operator console go:embed'd → ONE binary)
#   console/  canonical operator-UI source (copied into engine at build)
.PHONY: build engine test schema clean help

help:
	@echo "make build   - build the single engine binary (console embedded)"
	@echo "make test    - run the engine test suite"
	@echo "make schema  - regenerate docs/config-schema.json from the engine config"
	@echo "make clean    - remove build artifacts"

build: engine            ## the product: one binary with the console embedded

engine:
	$(MAKE) -C engine build

test:
	$(MAKE) -C engine test

schema:
	$(MAKE) -C engine schema

clean:
	$(MAKE) -C engine clean
