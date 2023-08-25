all: trust

MAIN_VERSION ?= $(shell git describe --always --dirty || echo no-git)
ifeq ($(MAIN_VERSION),$(filter $(MAIN_VERSION), "", no-git))
$(error "Bad value for MAIN_VERSION: '$(MAIN_VERSION)'")
endif

BOOTKIT_VERSION ?= "v0.0.10.230825"

GO_SRC_DIRS := pkg/ cmd/
GO_SRC := $(shell find $(GO_SRC_DIRS) -name "*.go")

VERSION_LDFLAGS=-X github.com/project-machine/trust/pkg/trust.Version=$(MAIN_VERSION) \
	-X github.com/project-machine/trust/pkg/trust.BootkitVersion=$(BOOTKIT_VERSION)
trust: .made-gofmt $(GO_SRC)
	go build -buildvcs=false -ldflags "$(VERSION_LDFLAGS)" -o trust ./cmd/trust/

.PHONY: gofmt
gofmt: .made-gofmt
.made-gofmt: $(GO_SRC)
	o=$$(gofmt -l -w $(GO_SRC_DIRS) 2>&1) && [ -z "$$o" ] || \
		{ echo "gofmt made changes: $$o" 1>&2; exit 1; }
	@touch $@

clean:
	rm -f trust

.PHONY: test
test: trust
	bats tests/keyset.bats
	bats tests/project.bats
	bats tests/sudi.bats
