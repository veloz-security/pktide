ARCH ?= x86_64
PLATFORM ?= $(if $(filter Darwin,$(shell uname -s)),macos,linux)
CC = gcc
HOST_CC ?= cc
MACOS_CC ?= clang
PYTHON ?= python3
RUNNER ?=

ifeq ($(ARCH),x86_64)
ARCH_FLAGS = -m64 -march=x86-64 -mtune=generic -mno-red-zone
else ifeq ($(ARCH),i386)
ARCH_FLAGS = -m32 -march=i486 -mtune=generic -mno-sse -mno-mmx -msoft-float
else
$(error ARCH must be x86_64 or i386)
endif

WARN = -Wall -Wextra -Werror -Wshadow -Wconversion -Wstrict-prototypes
BASE_FLAGS = -std=c99 -Os $(WARN) -ffreestanding -fno-builtin \
             -fno-stack-protector -fno-pie -fno-pic -fno-unwind-tables \
             -fno-asynchronous-unwind-tables -fno-ident -ffunction-sections -fdata-sections
CFLAGS ?=
LDFLAGS ?=
SOURCES = src/main.c src/runtime.c src/util.c src/decode.c src/filter.c src/start.S
BINARY = dist/pktide-$(ARCH)
MACOS_BINARY = dist/pktide-macos
MACOS_SOURCES = src/main.c src/runtime_macos.c src/capture_macos.c src/bpf_macos.c \
                src/util.c src/decode.c src/filter.c
MACOS_FLAGS = -std=c99 -Os $(WARN) -arch arm64 -arch x86_64 \
              -mmacosx-version-min=11.0 -fstack-protector-strong

.PHONY: all linux macos clean verify verify-macos test test-live test-macos \
        test-live-macos test-bpf-macos verify-linux test-linux test-live-linux sanitize both vm-init
ifeq ($(PLATFORM),macos)
all: macos
verify: verify-macos
test: test-macos
test-live: test-live-macos
else
all: $(BINARY)
verify: verify-linux
test: test-linux
test-live: test-live-linux
endif

linux: $(BINARY)
macos: $(MACOS_BINARY)

$(MACOS_BINARY): $(MACOS_SOURCES) src/core.h src/macos.h Makefile
	@mkdir -p dist
	$(MACOS_CC) $(MACOS_FLAGS) $(CFLAGS) -Wl,-dead_strip $(LDFLAGS) $(MACOS_SOURCES) -o $@
	codesign --force --sign - --timestamp=none $@

$(BINARY): $(SOURCES) src/core.h src/linux_abi.h Makefile
	@mkdir -p dist
	$(CC) $(ARCH_FLAGS) $(BASE_FLAGS) $(CFLAGS) -nostdlib -static -no-pie \
	  -Wl,--build-id=none,--gc-sections,-z,noexecstack $(LDFLAGS) $(SOURCES) -o $@

both:
	$(MAKE) PLATFORM=linux ARCH=x86_64 all
	$(MAKE) PLATFORM=linux ARCH=i386 all

verify-linux: $(BINARY)
	$(PYTHON) tests/verify_elf.py $(BINARY) $(ARCH)

test-linux: verify-linux
	$(PYTHON) tests/test_cli.py --binary $(BINARY) --runner '$(RUNNER)'

test-live-linux: verify-linux
	$(PYTHON) tests/test_live.py --binary $(BINARY) --runner '$(RUNNER)'

verify-macos: $(MACOS_BINARY)
	$(PYTHON) tests/verify_macos.py $(MACOS_BINARY)

test-macos: verify-macos test-bpf-macos
	$(PYTHON) tests/test_cli.py --binary $(MACOS_BINARY) --runner '$(RUNNER)'

test-live-macos: verify-macos
	$(PYTHON) tests/test_live.py --binary $(MACOS_BINARY) --runner '$(RUNNER)'

test-bpf-macos:
	@mkdir -p build
	$(HOST_CC) -std=c99 -g -O1 $(WARN) -fsanitize=address,undefined \
	  -fno-omit-frame-pointer -Isrc src/util.c src/bpf_macos.c tests/bpf_check.c -o build/bpf-check
	./build/bpf-check

sanitize:
	@mkdir -p build
	$(HOST_CC) -std=c99 -g -O1 $(WARN) -fsanitize=address,undefined \
	  -fno-omit-frame-pointer -Isrc src/util.c src/decode.c src/filter.c tests/parser_check.c -o build/parser-check
	./build/parser-check

vm-init:
	@mkdir -p build
	$(CC) $(ARCH_FLAGS) $(BASE_FLAGS) -Isrc -nostdlib -static -no-pie \
	  -Wl,--build-id=none,--gc-sections,-z,noexecstack tests/vm_init.c src/runtime.c src/util.c src/start.S -o build/vm-init-$(ARCH)

clean:
	rm -rf build dist tests/tmp
