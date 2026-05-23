CC = gcc
CFLAGS = -O3
LDFLAGS = -s
TARGET = agent
SRC = node_exporter.c
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRC) -o $(TARGET)
	strip $(TARGET)

install: $(TARGET)
	@echo "Installing $(TARGET) to $(BINDIR)..."
	install -D -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	@echo "Removing $(TARGET) from $(BINDIR)..."
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all install uninstall clean
