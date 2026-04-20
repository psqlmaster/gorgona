# ==============================================================================
# GORGONA PROJECT NATIVE MAKEFILE
# Versioning: Independent versions for Client and Server via Git tags
#   - Client Tags Requirement: gorgona-vX.Y.Z (e.g., gorgona-v1.0.0)
#   - Server Tags Requirement: gorgonad-vX.Y.Z (e.g., gorgonad-v2.1.5)
# ==============================================================================
# --- Version Extraction Logic ---
# Extracts numeric version from tags. Defaults to 0.0.0 if no tags match.
# ==============================================================================
CLIENT_VER := $(shell git describe --tags --match "gorgona-v*" --abbrev=0 2>/dev/null | sed 's/gorgona-v//' || echo "0.0.0")
SERVER_VER := $(shell git describe --tags --match "gorgonad-v*" --abbrev=0 2>/dev/null | sed 's/gorgonad-v//' || echo "0.0.0")

# --- Toolchain & Flags ---
CC      := gcc
CFLAGS  := -g -std=c99 -Wall -pthread -Icommon -Iclient -D_XOPEN_SOURCE=700 -D_POSIX_C_SOURCE=200809L
LDFLAGS := -lssl -lcrypto -lm

# Test Environment Flags
TEST_CFLAGS  := $(CFLAGS) $(shell pkg-config --cflags check 2>/dev/null || echo "")
TEST_LDFLAGS := $(LDFLAGS) $(shell pkg-config --libs check 2>/dev/null || echo "-lcheck -lrt -lsubunit")

# --- Source File Definitions ---
COMMON_SRC  := common/encrypt.c common/common.c common/admin_mesh.c

CLIENT_SRC  := client/gorgona.c client/globals.c client/alert_send.c \
               client/alert_listen.c client/config.c client/client_history.c \
               client/peer_manager.c $(COMMON_SRC)

SERVER_SRC  := server/gorgonad.c server/config.c server/gorgona_utils.c \
               server/server_handler.c server/snowflake.c server/alert_db.c \
               server/commands.c $(COMMON_SRC)

# --- Object File Logic ---
CLIENT_OBJ  := $(CLIENT_SRC:.c=.client.o)
SERVER_OBJ  := $(SERVER_SRC:.c=.server.o)

# TEST AUTOMATION:
# We exclude gorgona.client.o (main), but keep globals.client.o (logging logic and variables) 
CLIENT_CORE_OBJ := $(filter-out client/gorgona.client.o, $(CLIENT_OBJ))

TEST_CONFIG_OBJ       := test/test_config.o $(CLIENT_CORE_OBJ)
TEST_ALERT_LISTEN_OBJ := test/test_alert_listen.o $(CLIENT_CORE_OBJ)
TEST_GORGONA_OBJ      := test/test_gorgona.o $(CLIENT_CORE_OBJ)

TEST_EXEC := test/test_config test/test_alert_listen test/test_gorgona

# --- Build Rules ---

.PHONY: all clean rebuild test deb-changelog build-packages

all: gorgona gorgonad

# Client Build 
gorgona: $(CLIENT_OBJ)
	$(CC) $(CLIENT_OBJ) -o gorgona $(LDFLAGS)
	@echo ">> Gorgona Client $(CLIENT_VER) built successfully"

# Server Setup 
gorgonad: $(SERVER_OBJ)
	$(CC) $(SERVER_OBJ) -o gorgonad $(LDFLAGS)
	@echo ">> Gorgonad Server $(SERVER_VER) built successfully"

# Client object files
%.client.o: %.c
	$(CC) $(CFLAGS) -DVERSION=\"$(CLIENT_VER)\" -c $< -o $@

# Server object files
%.server.o: %.c
	$(CC) $(CFLAGS) -DVERSION=\"$(SERVER_VER)\" -c $< -o $@

# Test objects
test/%.o: test/%.c
	$(CC) $(TEST_CFLAGS) -c $< -o $@

# --- Tests ---
test: $(TEST_EXEC)
	@echo "Running automated test suite..."
	@for test in $(TEST_EXEC); do \
		echo "Executing $$test..."; \
		./$$test || exit 1; \
	done
	@echo "All tests passed successfully."

test/test_config: $(TEST_CONFIG_OBJ)
	$(CC) $(TEST_CONFIG_OBJ) -o $@ $(TEST_LDFLAGS)

test/test_alert_listen: $(TEST_ALERT_LISTEN_OBJ)
	$(CC) $(TEST_ALERT_LISTEN_OBJ) -o $@ $(TEST_LDFLAGS)

test/test_gorgona: $(TEST_GORGONA_OBJ)
	$(CC) $(TEST_GORGONA_OBJ) -o $@ $(TEST_LDFLAGS)

# --- Packaging and changelogs ---
deb-changelog:
	@echo "Updating debian/changelog..."
	@printf "gorgona-project (Server: %s, Client: %s) stable; urgency=medium\n\n" \
		"$(SERVER_VER)" "$(CLIENT_VER)" > debian/changelog.new
	@echo "  * Automated version synchronization from Git tags" >> debian/changelog.new
	@echo "  * Built at $$(date -R)" >> debian/changelog.new
	@echo "" >> debian/changelog.new
	@if [ -f debian/changelog ]; then cat debian/changelog >> debian/changelog.new; fi
	@mv debian/changelog.new debian/changelog

build-packages:
	@echo "Starting separate builds for Client ($(CLIENT_VER)) and Server ($(SERVER_VER))"
	@chmod +x build_packages.sh
	@./build_packages.sh "$(CLIENT_VER)" "$(SERVER_VER)"

# --- Cleaning ---
clean:
	@echo "Removing build artifacts..."
	rm -f $(CLIENT_OBJ) $(SERVER_OBJ) test/*.o
	rm -f gorgona gorgonad $(TEST_EXEC)
	find . -name "*.o" -type f -delete

rebuild: clean all
