# Kapkan monorepo — root orchestrator.
#   engine/   the Go binary (operator console go:embed'd → ONE binary)
#   console/  canonical operator-UI source (copied into engine at build)
#   site/     the kapkan.io static site (Next.js)
#   docs/     canonical user-facing MDX (copied into the site at build)
.PHONY: build engine test site clean help

help:
	@echo "make build   - build the single engine binary (console embedded)"
	@echo "make test    - run the engine test suite"
	@echo "make site    - build the static site (docs/ -> site/frontend/content/docs)"
	@echo "make clean    - remove build artifacts"

build: engine            ## the product: one binary with the console embedded

engine:
	$(MAKE) -C engine build

test:
	$(MAKE) -C engine test

site:
	cd site/frontend && npm run build

clean:
	$(MAKE) -C engine clean
