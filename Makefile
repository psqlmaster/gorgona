# Compiler and flags
CC = gcc
CFLAGS = -g -Wall -Icommon -DVERSION=\"$(VERSION)\"
LDFLAGS = -lssl -lcrypto

# Version definition from Git tag
VERSION = $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' | tr -d '\n' || echo "0.0.0")

# Default changelog message (used if no commits or CHANGELOG_MSG is not set)
DEFAULT_CHANGELOG_MSG = New release of gorgona client and server.

# Source files
gorgona_SRC = client/gorgona.c client/alert_send.c client/alert_listen.c client/config.c common/encrypt.c
gorgonaD_SRC = server/gorgonad.c server/gorgona_utils.c server/server_handler.c common/encrypt.c

# Object files
gorgona_OBJ = $(gorgona_SRC:.c=.o)
gorgonaD_OBJ = $(gorgonaD_SRC:.c=.o)

# Targets
all: gorgona gorgonad

# Build gorgona
gorgona: $(gorgona_OBJ)
	$(CC) $(gorgona_OBJ) -o gorgona $(LDFLAGS)

# Build gorgonad
gorgonad: $(gorgonaD_OBJ)
	$(CC) $(gorgonaD_OBJ) -o gorgonad $(LDFLAGS)

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Update debian/changelog with commit messages
deb-changelog:
	@echo "Updating debian/changelog with version $(VERSION)"
	@CURRENT_TAG=$$(git --no-pager describe --tags --abbrev=0 2>/dev/null); \
	CURRENT_TAG_OUT=$$(echo "$$CURRENT_TAG" | sed 's/^v//' | tr -d '\n' || echo "0.0.0"); \
	PREV_TAG=$$(git --no-pager tag --sort=-v:refname | grep -A 1 "$$CURRENT_TAG" | tail -n 1); \
	CHANGELOG_MESSAGE=$$(git --no-pager log --pretty="* %s" "$$PREV_TAG..$$CURRENT_TAG" 2>/dev/null | sort -u); \
	if [ -z "$$CHANGELOG_MESSAGE" ]; then CHANGELOG_MESSAGE="$(DEFAULT_CHANGELOG_MSG)"; fi; \
	{ \
		echo "gorgona ($$CURRENT_TAG_OUT) stable; urgency=medium"; \
		echo ""; \
		echo "$$CHANGELOG_MESSAGE" | sed 's/^/  /'; \
		echo ""; \
		echo " -- Aleksandr Scheglov <globalalek@gmail.com> $$(date -R)"; \
		echo ""; \
		cat debian/changelog; \
	} > debian/changelog.new; \
	mv debian/changelog.new debian/changelog; \
	echo "Changelog updated manually without dch"




# Build Debian packages
build-packages: deb-changelog
	@echo "Running build_packages.sh to build Debian packages with version $(VERSION)"
	@./build_packages.sh

# Clean up
clean:
	rm -f $(gorgona_OBJ) $(gorgonaD_OBJ) gorgona gorgonad

# Rebuild everything
rebuild: clean all

# Phony targets
.PHONY: all clean rebuild deb-changelog build-packages
