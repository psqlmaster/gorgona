# --- OpenWrt x86 (i386_pentium4) Cross-Compilation Makefile ---

SDK_DIR       = $(HOME)/crosscompile/openwrt

# ПУТИ ИЗ ТВОЕГО staging_dir
TOOLCHAIN_DIR = $(SDK_DIR)/staging_dir/toolchain-i386_pentium4_gcc-12.3.0_musl
TARGET_DIR    = $(SDK_DIR)/staging_dir/target-i386_pentium4_musl

# Имя компилятора (проверь в bin/, может быть i486 или i386)
CC = $(TOOLCHAIN_DIR)/bin/i486-openwrt-linux-musl-gcc

export STAGING_DIR = $(SDK_DIR)/staging_dir

# ФЛАГИ
VERSION = $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' | tr -d '\n' || echo "2.9.6")

CFLAGS = -Oz -std=c99 -Wall \
         -I../common -I../client \
         -I$(TARGET_DIR)/usr/include \
         -DVERSION=\"$(VERSION)\" -pthread \
         -D_XOPEN_SOURCE=700 -D_POSIX_C_SOURCE=200809L

LDFLAGS = -L$(TARGET_DIR)/usr/lib \
          -lssl -lcrypto -lm -lpthread

COMMON_SRC  = ../common/encrypt.c ../common/common.c
CLIENT_SRC  = ../client/gorgona.c ../client/alert_send.c ../client/alert_listen.c ../client/config.c $(COMMON_SRC)
SERVER_SRC  = ../server/gorgonad.c ../server/config.c ../server/gorgona_utils.c ../server/server_handler.c \
              ../server/snowflake.c ../server/alert_db.c ../server/commands.c ../server/admin_mesh.c $(COMMON_SRC)

all: info gorgona_owrt gorgonad_owrt

info:
	@echo "--- OpenWrt i386 Build Info ---"
	@echo "Target:    $(TARGET_DIR)"
	@echo "Compiler:  $(CC)"
	@echo "-------------------------------"

gorgona_owrt: $(CLIENT_SRC)
	$(CC) $(CFLAGS) $(CLIENT_SRC) -o gorgona_owrt $(LDFLAGS)

gorgonad_owrt: $(SERVER_SRC)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o gorgonad_owrt $(LDFLAGS)

clean:
	rm -f gorgona_owrt gorgonad_owrt

.PHONY: all clean info
