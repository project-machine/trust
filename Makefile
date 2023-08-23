all: trust

MAIN_VERSION ?= $(shell git describe --always --dirty || echo no-git)
ifeq ($(MAIN_VERSION),$(filter $(MAIN_VERSION), "", no-git))
$(error "Bad value for MAIN_VERSION: '$(MAIN_VERSION)'")
endif

VERSION_LDFLAGS=-X github.com/project-machine/trust/pkg/trust.Version=$(MAIN_VERSION)
trust: cmd/trust/*.go pkg/trust/*.go pkg/printdirtree/*.go
	go build -buildvcs=false -ldflags "$(VERSION_LDFLAGS)" -o trust ./cmd/trust/

clean:
	rm -f trust

.PHONY: test
test: trust
	bats tests/keyset.bats
	bats tests/project.bats
	bats tests/sudi.bats
