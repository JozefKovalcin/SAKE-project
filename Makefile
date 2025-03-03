# Detect operating system
ifeq ($(OS),Windows_NT)
    CC = gcc
    CFLAGS = -Wall -Wextra -O2
    LIBS = -lws2_32 -lbcrypt
    RM = del /Q /F
    EXT = .exe
else
    CC = gcc
    CFLAGS = -Wall -Wextra -O2
    LIBS = -lpthread
    RM = rm -f
    EXT =
endif

# Source files
COMMON_SRC = monocypher.c siete.c crypto_utils.c
SERVER_SRC = server.c $(COMMON_SRC)
CLIENT_SRC = client.c $(COMMON_SRC)

# Header files for dependency tracking
HEADERS = monocypher.h siete.h crypto_utils.h constants.h

# Output executables
SERVER = server$(EXT)
CLIENT = client$(EXT)

# Build targets
all: $(SERVER) $(CLIENT)

# Server compilation
$(SERVER): $(SERVER_SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SERVER_SRC) $(LIBS)

# Client compilation
$(CLIENT): $(CLIENT_SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRC) $(LIBS)

# Clean target
clean:
	$(RM) $(SERVER) $(CLIENT)

# Help target
help:
	@echo "Available targets:"
	@echo "  all      - Build both server and client (default)"
	@echo "  server   - Build only server"
	@echo "  client   - Build only client"
	@echo "  clean    - Remove compiled files"
	@echo "  help     - Show this help message"

.PHONY: all clean help