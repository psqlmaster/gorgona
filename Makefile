# ==============================================================================
# GORGONA PROJECT NATIVE MAKEFILE
# Versioning: Independent versions for Client and Server via Git tags
#   - Client Tags Requirement: gorgona-vX.Y.Z (e.g., gorgona-v1.0.0)
#   - Server Tags Requirement: gorgonad-vX.Y.Z (e.g., gorgonad-v2.1.5)
# ==============================================================================
# --- Version Extraction Logic ---
# Extracts numeric version from tags. Defaults to 0.0.0 if no tags match.
CLIENT_VER := $(shell git describe --tags --match "gorgona-v*" --abbrev=0 2>/dev/null | sed 's/gorgona-v//' || echo "0.0.0")
SERVER_VER := $(shell git describe --tags --match "gorgonad-v*" --abbrev=0 2>/dev/null | sed 's/gorgonad-v//' || echo "0.0.0")

# --- Toolchain & Flags Selection ---
CC      := gcc
CFLAGS  := -g -std=c99 -Wall -pthread -Icommon -Iclient -D_XOPEN_SOURCE=700 -D_POSIX_C_SOURCE=200809L
LDFLAGS := -lssl -lcrypto -lm

# Test Environment Flags (Check library requirement)
TEST_CFLAGS  := $(CFLAGS) $(shell pkg-config --cflags check 2>/dev/null || echo "")
TEST_LDFLAGS := $(LDFLAGS) $(shell pkg-config --libs check 2>/dev/null || echo "-lcheck")

# --- Source File Definitions ---
# Common files used by both Client and Server
COMMON_SRC  := common/encrypt.c common/common.c

CLIENT_SRC  := client/gorgona.c client/alert_send.c client/alert_listen.c client/config.c $(COMMON_SRC)
SERVER_SRC  := server/gorgonad.c server/config.c server/gorgona_utils.c server/server_handler.c \
               server/snowflake.c server/alert_db.c server/commands.c server/admin_mesh.c $(COMMON_SRC)

TEST_SRC    := test/test_config.c test/test_alert_listen.c test/test_gorgona.c

# --- Object File Logic ---
# Using distinct extensions (.client.o / .server.o) is critical because 
# shared files in common/ must be compiled twice with different VERSION macros.
CLIENT_OBJ  := $(CLIENT_SRC:.c=.client.o)
SERVER_OBJ  := $(SERVER_SRC:.c=.server.o)
TEST_OBJ    := $(TEST_SRC:.c=.o)

# Test dependencies mapped to client-specific objects
TEST_CONFIG_OBJ       := test/test_config.o client/alert_send.client.o client/alert_listen.client.o \
                         client/config.client.o common/encrypt.client.o common/common.client.o
TEST_ALERT_LISTEN_OBJ := test/test_alert_listen.o client/alert_send.client.o client/alert_listen.client.o \
                         client/config.client.o common/encrypt.client.o common/common.client.o
TEST_GORGONA_OBJ      := test/test_gorgona.o

TEST_EXEC := test/test_config test/test_alert_listen test/test_gorgona

# --- Build Rules ---

.PHONY: all clean rebuild test deb-changelog

all: gorgona gorgonad

# Build Gorgona Client
gorgona: $(CLIENT_OBJ)
	$(CC) $(CLIENT_OBJ) -o gorgona $(LDFLAGS)
	@echo ">> Gorgona Client $(CLIENT_VER) built successfully"

# Build Gorgona Server Daemon
gorgonad: $(SERVER_OBJ)
	$(CC) $(SERVER_OBJ) -o gorgonad $(LDFLAGS)
	@echo ">> Gorgonad Server $(SERVER_VER) built successfully"

# Compiles Client Objects injecting the CLIENT_VER into the VERSION macro
%.client.o: %.c
	$(CC) $(CFLAGS) -DVERSION=\"$(CLIENT_VER)\" -c $< -o $@

# Compiles Server Objects injecting the SERVER_VER into the VERSION macro
%.server.o: %.c
	$(CC) $(CFLAGS) -DVERSION=\"$(SERVER_VER)\" -c $< -o $@

# Compiles Test Objects
test/%.o: test/%.c
	$(CC) $(TEST_CFLAGS) -c $< -o $@

# --- Test Suite ---
test: $(TEST_EXEC)
	@echo "Running automated test suite..."
	@for test in $(TEST_EXEC); do \
		echo "Executing $$test..."; \
		./$$test || exit 1; \
	done
	@echo "All tests passed successfully."

test/test_config: $(TEST_CONFIG_OBJ)
	$(CC) $^ -o $@ $(TEST_LDFLAGS)

test/test_alert_listen: $(TEST_ALERT_LISTEN_OBJ)
	$(CC) $^ -o $@ $(TEST_LDFLAGS)

test/test_gorgona: $(TEST_GORGONA_OBJ)
	$(CC) $^ -o $@ $(TEST_LDFLAGS)

# --- Debian Package Maintenance ---
deb-changelog:
	@echo "Updating debian/changelog..."
	@printf "gorgona-project (Server: %s, Client: %s) stable; urgency=medium\n\n" \
		"$(SERVER_VER)" "$(CLIENT_VER)" > debian/changelog.new
	@echo "  * Automated version synchronization from Git tags" >> debian/changelog.new
	@echo "  * Built at $$(date -R)" >> debian/changelog.new
	@echo "" >> debian/changelog.new
	@if [ -f debian/changelog ]; then cat debian/changelog >> debian/changelog.new; fi
	@mv debian/changelog.new debian/changelog
# Main target for package building
# We pass versions as arguments to the script
build-packages:
	@echo "Starting separate builds for Client ($(CLIENT_VER)) and Server ($(SERVER_VER))"
	@chmod +x build_packages.sh
	@./build_packages.sh "$(CLIENT_VER)" "$(SERVER_VER)"
# --- Cleanup ---
clean:
	@echo "Removing build artifacts..."
	rm -f $(CLIENT_OBJ) $(SERVER_OBJ) $(TEST_OBJ)
	rm -f gorgona gorgonad $(TEST_EXEC)
	find . -name "*.o" -type f -delete

rebuild: clean all
