# Compiler and flags
CC = gcc
CFLAGS = -g -Wall -Icommon
LDFLAGS = -lssl -lcrypto

# Source files
GARGONA_SRC = client/gargona.c client/alert_send.c client/alert_listen.c client/config.c common/encrypt.c
GARGONAD_SRC = server/gargonad.c server/gargona_utils.c server/server_handler.c common/encrypt.c

# Object files
GARGONA_OBJ = $(GARGONA_SRC:.c=.o)
GARGONAD_OBJ = $(GARGONAD_SRC:.c=.o)

# Targets
all: gargona gargonad

# Build gargona
gargona: $(GARGONA_OBJ)
	$(CC) $(GARGONA_OBJ) -o gargona $(LDFLAGS)

# Build gargonad
gargonad: $(GARGONAD_OBJ)
	$(CC) $(GARGONAD_OBJ) -o gargonad $(LDFLAGS)

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(GARGONA_OBJ) $(GARGONAD_OBJ) gargona gargonad

# Rebuild everything
rebuild: clean all

# Phony targets
.PHONY: all clean rebuild
