# --- Gorgona Multi-SDK Cross-Compilation Makefile for aarch64 ---
# Architecture: aarch64 (ARM64 Routers, e.g., RPi, NanoPi)
# OS Target: OpenWrt (musl libc)

SDK_ROOT = $(HOME)/crosscompile
# Find only folders related to aarch64 SDKs (ignore .tar.xz and .tar.zst files)
SDKS = $(shell find $(SDK_ROOT) -maxdepth 1 -type d -name "openwrt-sdk-*aarch64*")

# Retrieve software versions from Git tags
CLIENT_VER := $(shell git describe --tags --match "gorgona-v*" --abbrev=0 2>/dev/null | sed 's/gorgona-v//' || echo "0.0.0")
SERVER_VER := $(shell git describe --tags --match "gorgonad-v*" --abbrev=0 2>/dev/null | sed 's/gorgonad-v//' || echo "0.0.0")

# Define source paths relative to this directory (../../)
# 1. COMMON_SRC: Now includes admin_mesh.c since it's shared in the common folder
COMMON_SRC  = ../../common/encrypt.c ../../common/common.c ../../common/admin_mesh.c

# 2. CLIENT_SRC: Added globals.c and peer_manager.c
CLIENT_SRC  = ../../client/gorgona.c \
              ../../client/globals.c \
              ../../client/alert_send.c \
              ../../client/alert_listen.c \
              ../../client/config.c \
              ../../client/client_history.c \
              ../../client/peer_manager.c \
              $(COMMON_SRC)

# 3. SERVER_SRC: Corrected paths to point to current architecture
SERVER_SRC  = ../../server/gorgonad.c \
              ../../server/config.c \
              ../../server/gorgona_utils.c \
              ../../server/server_handler.c \
              ../../server/snowflake.c \
              ../../server/alert_db.c \
              ../../server/commands.c \
              $(COMMON_SRC)

# Iterate through all discovered SDKs and run the build-one target
all:
	@if [ -z "$(SDKS)" ]; then echo "No aarch64 SDKs found in $(SDK_ROOT)"; exit 1; fi
	@for sdk in $(SDKS); do \
		$(MAKE) --no-print-directory build-one SDK_DIR=$$sdk; \
	done

build-one:
	@# Retrieve the OpenWrt version from the SDK's .config (fallback to folder name)
	@V=$$(grep "CONFIG_VERSION_NUMBER=" $(SDK_DIR)/.config 2>/dev/null | cut -d'=' -f2 | tr -d '"'); \
	if [ -z "$$V" ]; then V=$$(basename $(SDK_DIR) | cut -d'-' -f3); fi; \
	\
	# Locate dynamic paths inside the SDK's staging_dir \
	STAGING_DIR=$${SDK_DIR}/staging_dir; \
	TOOLCHAIN_DIR=$$(ls -d $${STAGING_DIR}/toolchain-aarch64_* 2>/dev/null | head -n 1); \
	TARGET_DIR=$$(ls -d $${STAGING_DIR}/target-aarch64_* 2>/dev/null | head -n 1); \
	\
	# Set the cross-compiler binary path \
	CC=$${TOOLCHAIN_DIR}/bin/aarch64-openwrt-linux-musl-gcc; \
	\
	# Verify that the SDK dependencies (OpenSSL headers) are ready \
	if [ ! -f "$${TARGET_DIR}/usr/include/openssl/evp.h" ]; then \
		echo "-------------------------------------------------------"; \
		echo "Skipping: OpenWrt $$V (OpenSSL headers missing)"; \
		echo "Solution: cd $$SDK_DIR && make package/libs/openssl/install"; \
	else \
		echo "-------------------------------------------------------"; \
		echo "Target System: OpenWrt $$V (aarch64)"; \
		\
		# The OpenWrt toolchain wrapper requires STAGING_DIR to be in environment \
		export STAGING_DIR=$${STAGING_DIR}; \
		\
		# Build Gorgona Client for the current target OS version \
		$${CC} -Oz -std=c99 -Wall -pthread -D_XOPEN_SOURCE=700 -D_POSIX_C_SOURCE=200809L \
			-DVERSION=\"$(CLIENT_VER)\" \
			-I../../common -I../../client \
			-I$${TARGET_DIR}/usr/include \
			$(CLIENT_SRC) -o gorgona_aarch64_$$V \
			-L$${TARGET_DIR}/usr/lib -lssl -lcrypto -lm -lpthread; \
		\
		# Build Gorgona Server for the current target OS version \
		$${CC} -Oz -std=c99 -Wall -pthread -D_XOPEN_SOURCE=700 -D_POSIX_C_SOURCE=200809L \
			-DVERSION=\"$(SERVER_VER)\" \
			-I../../common -I../../client -I"../../server" \
			-I$${TARGET_DIR}/usr/include \
			$(SERVER_SRC) -o gorgonad_aarch64_$$V \
			-L$${TARGET_DIR}/usr/lib -lssl -lcrypto -lm -lpthread; \
		\
		echo "Output: gorgona_aarch64_$$V, gorgonad_aarch64_$$V"; \
	fi

# Cleanup binaries for all versions
clean:
	rm -f gorgona_aarch64_* gorgonad_aarch64_*

.PHONY: all clean build-one
