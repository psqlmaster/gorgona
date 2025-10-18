# Compiler and flags
CC = gcc
CFLAGS = -g -Wall -Icommon -DVERSION=\"1.8.6\"
LDFLAGS = -lssl -lcrypto

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

# Clean up
clean:
	rm -f $(gorgona_OBJ) $(gorgonaD_OBJ) gorgona gorgonad

# Rebuild everything
rebuild: clean all

# Phony targets
.PHONY: all clean rebuild
