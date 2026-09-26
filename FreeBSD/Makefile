# ==============================================================================
# GORGONA PROJECT NATIVE MAKEFILE FOR FREEBSD / OPNSENSE
# Designed for GNU Make (gmake) on FreeBSD
# ==============================================================================

# Root directory of the repository relative to this Makefile
ROOT_DIR   := ..

# --- Version Extraction Logic ---
CLIENT_VER := $(or $(shell git -C $(ROOT_DIR) describe --tags --match "gorgona-v*" --abbrev=0 2>/dev/null | sed 's/gorgona-v//'),0.0.0)
SERVER_VER := $(or $(shell git -C $(ROOT_DIR) describe --tags --match "gorgonad-v*" --abbrev=0 2>/dev/null | sed 's/gorgonad-v//'),0.0.0)

# Default FreeBSD system compiler is Clang (cc)
CC         ?= cc

# --- Toolchain & Flags for FreeBSD ---
OPT_FLAGS  := -O1
DEBUG_LDFLAGS :=

# FreeBSD requires -I/usr/local/include and -D__BSD_VISIBLE=1 for networking & OpenSSL
CFLAGS     := $(OPT_FLAGS) -std=gnu11 -Wall -pthread \
              -I/usr/local/include \
              -I$(ROOT_DIR)/common \
              -I$(ROOT_DIR)/client \
              -D_XOPEN_SOURCE=700 \
              -D_POSIX_C_SOURCE=200809L \
              -D__BSD_VISIBLE=1

# FreeBSD requires -L/usr/local/lib to link OpenSSL from ports/base
LDFLAGS    := $(DEBUG_LDFLAGS) -L/usr/local/lib -lssl -lcrypto -lm -pthread

# Test Environment Flags (FreeBSD uses /usr/local/libdata/pkgconfig for check)
PKG_CONFIG_ENV := PKG_CONFIG_PATH="/usr/local/libdata/pkgconfig:/usr/local/lib/pkgconfig:$$PKG_CONFIG_PATH"
TEST_CFLAGS    := $(CFLAGS) $(shell $(PKG_CONFIG_ENV) pkg-config --cflags check 2>/dev/null || echo "")
TEST_LDFLAGS   := $(LDFLAGS) $(shell $(PKG_CONFIG_ENV) pkg-config --libs check 2>/dev/null || echo "-lcheck -lm")

# --- Source File Definitions ---
COMMON_SRC := $(ROOT_DIR)/common/encrypt.c \
              $(ROOT_DIR)/common/common.c \
              $(ROOT_DIR)/common/admin_mesh.c

CLIENT_SRC := $(ROOT_DIR)/client/gorgona.c \
              $(ROOT_DIR)/client/globals.c \
              $(ROOT_DIR)/client/alert_send.c \
              $(ROOT_DIR)/client/alert_listen.c \
              $(ROOT_DIR)/client/config.c \
              $(ROOT_DIR)/client/client_history.c \
              $(ROOT_DIR)/client/peer_manager.c \
              $(COMMON_SRC)

SERVER_SRC := $(ROOT_DIR)/server/gorgonad.c \
              $(ROOT_DIR)/server/config.c \
              $(ROOT_DIR)/server/gorgona_utils.c \
              $(ROOT_DIR)/server/server_handler.c \
              $(ROOT_DIR)/server/snowflake.c \
              $(ROOT_DIR)/server/alert_db.c \
              $(ROOT_DIR)/server/commands.c \
              $(ROOT_DIR)/server/metrics.c \
              $(ROOT_DIR)/server/alert_chaining.c \
              $(COMMON_SRC)

# --- Object File Logic ---
CLIENT_OBJ := $(CLIENT_SRC:.c=.client.o)
SERVER_OBJ := $(SERVER_SRC:.c=.server.o)

CLIENT_CORE_OBJ := $(filter-out $(ROOT_DIR)/client/gorgona.client.o, $(CLIENT_OBJ))

TEST_CONFIG_OBJ       := $(ROOT_DIR)/test/test_config.o $(CLIENT_CORE_OBJ)
TEST_ALERT_LISTEN_OBJ := $(ROOT_DIR)/test/test_alert_listen.o $(CLIENT_CORE_OBJ)
TEST_GORGONA_OBJ      := $(ROOT_DIR)/test/test_gorgona.o $(CLIENT_CORE_OBJ)

TEST_EXEC := $(ROOT_DIR)/test/test_config \
             $(ROOT_DIR)/test/test_alert_listen \
             $(ROOT_DIR)/test/test_gorgona

# --- Targets ---
CLIENT_BIN := $(ROOT_DIR)/gorgona
SERVER_BIN := $(ROOT_DIR)/gorgonad

.PHONY: all clean rebuild test

all: $(CLIENT_BIN) $(SERVER_BIN)

# Client Build 
$(CLIENT_BIN): $(CLIENT_OBJ)
	$(CC) $(CLIENT_OBJ) -o $@ $(LDFLAGS)
	@ln -sf $@ ./gorgona
	@echo ">> Gorgona Client $(CLIENT_VER) built successfully for FreeBSD: $@"

# Server Build 
$(SERVER_BIN): $(SERVER_OBJ)
	$(CC) $(SERVER_OBJ) -o $@ $(LDFLAGS)
	@ln -sf $@ ./gorgonad
	@echo ">> Gorgonad Server $(SERVER_VER) built successfully for FreeBSD: $@"

# Client object compilation
%.client.o: %.c
	$(CC) $(CFLAGS) -DVERSION=\"$(CLIENT_VER)\" -c $< -o $@

# Server object compilation
%.server.o: %.c
	$(CC) $(CFLAGS) -DVERSION=\"$(SERVER_VER)\" -c $< -o $@

# Test object compilation
$(ROOT_DIR)/test/%.o: $(ROOT_DIR)/test/%.c
	$(CC) $(TEST_CFLAGS) -c $< -o $@

# --- Tests ---
test: $(TEST_EXEC)
	@echo "Running automated test suite on FreeBSD..."
	@for t in $(TEST_EXEC); do \
		echo "Executing $$t..."; \
		$$t || exit 1; \
	done
	@echo "All tests passed successfully."

$(ROOT_DIR)/test/test_config: $(TEST_CONFIG_OBJ)
	$(CC) $(TEST_CONFIG_OBJ) -o $@ $(TEST_LDFLAGS)

$(ROOT_DIR)/test/test_alert_listen: $(TEST_ALERT_LISTEN_OBJ)
	$(CC) $(TEST_ALERT_LISTEN_OBJ) -o $@ $(TEST_LDFLAGS)

$(ROOT_DIR)/test/test_gorgona: $(TEST_GORGONA_OBJ)
	$(CC) $(TEST_GORGONA_OBJ) -o $@ $(TEST_LDFLAGS)

# --- Cleaning ---
clean:
	@echo "Removing FreeBSD build artifacts..."
	rm -f $(CLIENT_OBJ) $(SERVER_OBJ) $(ROOT_DIR)/test/*.o
	rm -f $(CLIENT_BIN) $(SERVER_BIN) ./gorgona ./gorgonad $(TEST_EXEC)
	find $(ROOT_DIR) -name "*.client.o" -type f -delete
	find $(ROOT_DIR) -name "*.server.o" -type f -delete

rebuild: clean all
