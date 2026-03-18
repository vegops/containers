SHELL := /bin/sh

# Registry and tagging
REGISTRY ?= ghcr.io
OWNER ?= vegops
IMAGE_PREFIX := $(REGISTRY)/$(OWNER)
ARCH ?= aarch64
TAG ?= test

# Build artifacts
SIGNING_KEY ?= melange.rsa
KEYRING ?= melange.rsa.pub
PACKAGES_DIR ?= packages
OUT_DIR ?= out

# Security scanning
TRIVY ?= trivy
TRIVY_FAIL_SEVERITY ?= CRITICAL,HIGH
TRIVY_ALL_SEVERITY ?= CRITICAL,HIGH,MEDIUM,LOW

# Tooling
DOCKER ?= docker
MELANGE = $(DOCKER) run --rm --privileged -v $(CURDIR):/work -w /work cgr.dev/chainguard/melange
APKO = $(DOCKER) run --rm -v $(CURDIR):/work -w /work cgr.dev/chainguard/apko

# Package discovery
MELANGE_PACKAGES := $(sort $(patsubst %/melange.yaml,%,$(wildcard */melange.yaml)))
APKO_PACKAGES := $(sort $(patsubst %/apko.yaml,%,$(wildcard */apko.yaml)))
PACKAGES := $(sort $(MELANGE_PACKAGES) $(APKO_PACKAGES))

# Arch names used by docker after `apko build` + `docker load`
DOCKER_ARCH := $(if $(filter $(ARCH),x86_64),amd64,$(if $(filter $(ARCH),aarch64),arm64,$(ARCH)))

define IMAGE
$(IMAGE_PREFIX)/$(1):$(2)
endef

define TARBALL
$(OUT_DIR)/$(1)-$(ARCH).tar
endef

.PHONY: all help list keygen clean clean-images melange apko build test scan scan-all push

all: help

help:
	@echo "Usage:"
	@echo "  make list                 List discovered packages"
	@echo "  make build                Build all images"
	@echo "  make build-<package>      Build melange/test/apko flow for one package"
	@echo "  make melange              Build all Melange packages"
	@echo "  make melange-<package>    Build only the Melange package"
	@echo "  make test                 Run Melange tests for all packages that support them"
	@echo "  make test-<package>       Run Melange tests for one package"
	@echo "  make scan                 Run Trivy scan on all local images tagged $(TAG)"
	@echo "  make scan-<package>       Run Trivy scan on one local image"
	@echo "  make scan-all             Run full Trivy scan (includes MEDIUM/LOW)"
	@echo "  make apko                 Build all Apko images"
	@echo "  make apko-<package>       Build only the Apko image"
	@echo "  make push                 Push all local images tagged $(TAG)"
	@echo "  make push-<package>       Push one local image tagged $(TAG)"
	@echo "  make keygen               Generate Melange signing keys if missing"
	@echo "  make clean                Remove local build artifacts"
	@echo "  make clean-images         Remove locally tagged images"
	@echo ""
	@echo "Variables:"
	@echo "  REGISTRY=$(REGISTRY)"
	@echo "  OWNER=$(OWNER)"
	@echo "  ARCH=$(ARCH)"
	@echo "  TAG=$(TAG)"
	@echo ""
	@echo "Discovered packages: $(PACKAGES)"

list:
	@printf '%s\n' $(PACKAGES)

melange: $(addprefix melange-,$(MELANGE_PACKAGES))

apko: $(addprefix apko-,$(APKO_PACKAGES))

build: $(addprefix build-,$(APKO_PACKAGES))

test: $(addprefix test-,$(MELANGE_PACKAGES))

scan: $(addprefix scan-,$(APKO_PACKAGES))

scan-all: $(addprefix scan-full-,$(APKO_PACKAGES))

push: $(addprefix push-,$(APKO_PACKAGES))

keygen:
	@if [ ! -f "$(SIGNING_KEY)" ] || [ ! -f "$(KEYRING)" ]; then \
		echo "Generating Melange signing keys..."; \
		$(MELANGE) keygen; \
	else \
		echo "Melange signing keys already present"; \
	fi

$(PACKAGES_DIR) $(OUT_DIR):
	mkdir -p $@

melange-%: keygen $(PACKAGES_DIR)
	@if [ -f "./$*/melange.yaml" ]; then \
		echo "Building Melange package $* for $(ARCH)..."; \
		$(MELANGE) build ./$*/melange.yaml \
			--arch $(ARCH) \
			--signing-key /work/$(SIGNING_KEY) \
			--repository-append /work/$(PACKAGES_DIR) \
			--keyring-append /work/$(KEYRING) \
			--out-dir /work/$(PACKAGES_DIR); \
		$(MELANGE) index \
			--signing-key /work/$(SIGNING_KEY) \
			-o /work/$(PACKAGES_DIR)/$(ARCH)/APKINDEX.tar.gz \
			./$(PACKAGES_DIR)/$(ARCH)/*.apk; \
	else \
		echo "No melange.yaml found for $*"; \
	fi

melangecheck-%: keygen $(PACKAGES_DIR)
	@if [ -f "./$*/melange.yaml" ]; then \
		echo "Running Melange tests for $* on $(ARCH)..."; \
		$(MELANGE) test ./$*/melange.yaml \
			--arch $(ARCH) \
			--repository-append /work/$(PACKAGES_DIR) \
			--keyring-append /work/$(KEYRING); \
	else \
		echo "No melange.yaml found for $*"; \
	fi

test-%:
	@$(MAKE) melange-$*
	@$(MAKE) melangecheck-$*

apko-%: keygen $(OUT_DIR)
	@if [ -f "./$*/apko.yaml" ]; then \
		echo "Building Apko image $* for $(ARCH)..."; \
		rm -f "$(call TARBALL,$*)"; \
		$(APKO) build ./$*/apko.yaml \
			"$(call IMAGE,$*,$(TAG))" \
			"$(call TARBALL,$*)" \
			--arch $(ARCH) \
			--repository-append /work/$(PACKAGES_DIR) \
			--keyring-append /work/$(KEYRING); \
		$(DOCKER) load < "$(call TARBALL,$*)"; \
		$(DOCKER) tag "$(call IMAGE,$*,$(TAG))-$(DOCKER_ARCH)" "$(call IMAGE,$*,$(TAG))" 2>/dev/null || true; \
	else \
		echo "No apko.yaml found for $*"; \
	fi

build-%:
	@$(MAKE) melange-$*
	@$(MAKE) melangecheck-$*
	@$(MAKE) apko-$*

scan-%: apko-%
	@echo "Scanning $(call IMAGE,$*,$(TAG)) with Trivy..."
	@$(TRIVY) image --exit-code 1 --severity $(TRIVY_FAIL_SEVERITY) "$(call IMAGE,$*,$(TAG))"

scan-full-%: apko-%
	@echo "Running full Trivy scan for $(call IMAGE,$*,$(TAG))..."
	@$(TRIVY) image --severity $(TRIVY_ALL_SEVERITY) "$(call IMAGE,$*,$(TAG))"

push-%: apko-%
	@echo "Pushing $(call IMAGE,$*,$(TAG))..."
	@$(DOCKER) push "$(call IMAGE,$*,$(TAG))"

clean:
	rm -rf $(PACKAGES_DIR) $(OUT_DIR)
	rm -f sbom-*.spdx.json

clean-images:
	@for pkg in $(APKO_PACKAGES); do \
		$(DOCKER) rmi "$(IMAGE_PREFIX)/$$pkg:$(TAG)" 2>/dev/null || true; \
		$(DOCKER) rmi "$(IMAGE_PREFIX)/$$pkg:$(TAG)-$(DOCKER_ARCH)" 2>/dev/null || true; \
	done
