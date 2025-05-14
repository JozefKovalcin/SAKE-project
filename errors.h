#ifndef ERRORS_H
#define ERRORS_H

// Zakladne chybove spravy
#define ERR_SOCKET_SETUP "Error: Failed to set up server socket on port %d (%s)\n"
#define ERR_CLIENT_ACCEPT "Error: Failed to accept client connection (%s)\n"
#define ERR_HANDSHAKE "Error: Failed during initial handshake - check network connection\n"
#define ERR_SALT_RECEIVE "Error: Failed to receive salt from client\n"
#define ERR_SALT_SEND "Error: Failed to send salt to server\n"
#define ERR_KEY_DERIVATION "Error: Key derivation failed\n"
#define ERR_KEY_ACK "Error: Failed to send key acknowledgment\n"
#define ERR_SESSION_SETUP "Error: Failed to start session setup\n"
#define ERR_KEY_EXCHANGE "Error: Key exchange failed\n"
#define ERR_SESSION_NONCE "Error: Failed to receive session nonce\n"
#define ERR_SESSION_CONFIRM "Error: Failed to confirm session setup\n"
#define ERR_FILENAME_RECEIVE "Error: Failed to receive file name from client (%s)\n"
#define ERR_FILE_CREATE "Error: Failed to create file '%s' (%s)\n"
#define ERR_CHUNK_SIZE "Error: Failed to read chunk size\n"
#define ERR_CHUNK_PROCESS "Error: Failed to process chunk\n"
#define ERR_TRANSFER_INTERRUPTED "Error: File transfer failed or was interrupted prematurely\n"

// Chybove spravy pre sietove operacie
#define ERR_WINSOCK_INIT "Error: Winsock initialization failed\n"
#define ERR_SOCKET_CREATE "Error: Socket creation error\n"
#define ERR_SOCKET_BIND "Error: Bind failed (%s)\n"
#define ERR_SOCKET_LISTEN "Error: Listen failed (%s)\n"
#define ERR_SOCKET_ACCEPT "Error: Accept failed\n"
#define ERR_INVALID_ADDRESS "Error: Invalid address or port\n"
#define ERR_CONNECTION_FAILED "Error: Connection failed\n"
#define ERR_READY_SIGNAL "Error: Failed to send ready signal\n"
#define ERR_READY_RECEIVE "Error: Failed to receive ready signal\n"
#define ERR_KEY_ACK_SEND "Error: Failed to send key acknowledgment (sent %d bytes)\n"
#define ERR_KEY_ACK_RECEIVE "Error: Failed to receive key acknowledgment (received %d bytes)\n"
#define ERR_KEY_ACK_INVALID "Error: Invalid key acknowledgment received ('%.*s')\n"
#define ERR_SYNC_SEND "Failed to send sync message\n"
#define ERR_SYNC_INVALID "Invalid sync acknowledgment\n"
#define ERR_SYNC_MESSAGE "Invalid sync message\n"
#define ERR_SYNC_ACK_SEND "Failed to send sync acknowledgment\n"

// Chybove spravy pre rotaciu klucov
#define ERR_KEY_VALIDATE_SIGNAL "Error: Failed to receive validation marker\n"
#define ERR_KEY_VALIDATE_RECEIVE "Error: Failed to receive key validation\n"
#define ERR_KEY_VALIDATE_MISMATCH "Error: Key validation failed - keys do not match\n"
#define ERR_KEY_ROTATION_READY "Error: Failed to confirm key rotation\n"
#define ERR_NEW_CLIENT_NONCE_SEND "Error: Failed to send new client nonce\n"
#define ERR_NEW_CLIENT_NONCE_RECEIVE "Error: Failed to receive new client nonce\n"
#define ERR_NEW_SERVER_NONCE_SEND "Error: Failed to send new server nonce\n"
#define ERR_NEW_SERVER_NONCE_RECEIVE "Error: Failed to receive new server nonce\n"

// Chybove spravy pre casove limity
#define ERR_TIMEOUT_RECV "Error: Failed to set receive timeout (%s)\n"
#define ERR_TIMEOUT_SEND "Error: Failed to set send timeout (%s)\n"
#define ERR_KEEPALIVE "Warning: Failed to set keepalive\n"

// Chybove spravy pre kryptograficke operacie
#define ERR_RANDOM_LINUX "Error: Failed to generate random bytes (%s)\n"
#define ERR_RANDOM_WINDOWS "Error: Failed to generate random bytes (BCrypt error)\n"
#define ERR_KEY_DERIVE_PARAMS "Error: Invalid parameters for key derivation\n"
#define ERR_KEY_DERIVE_MEMORY "Error: Failed to allocate memory for key derivation\n"

// Chybove spravy pre nastavenia klienta
#define ERR_IP_ADDRESS_READ "Error: Failed to read IP address\n"
#define ERR_PORT_READ "Error: Failed to read port number\n"
#define ERR_PORT_INVALID "Error: Invalid port number. Please enter a value between 1 and 65535.\n"
#define IP_ADDR_READ "Error: Failed to read IP address\n"

// Chybove spravy pre odosielanie suborov
#define ERR_FILENAME_LENGTH "Error: File name exceeds maximum length of 239 characters\n"
#define ERR_FILENAME_READ "Error: Failed to read file name from input\n"
#define ERR_FILE_OPEN "Error: Cannot open file '%s' (%s)\n"
#define ERR_FILENAME_SEND "Error: Failed to send file name to server (%s)\n"
#define ERR_KEY_ROTATION_ACK "Error: Failed to acknowledge key rotation\n"
#define ERR_SERVER_ACK "Error: Server did not acknowledge successful transfer completion.\n"

// SAKE chybove spravy
#define ERR_CLIENT_NONCE_SEND "Error: Failed to send client nonce\n"
#define ERR_SERVER_CHALLENGE "Error: Failed to receive server challenge\n"
#define ERR_COMPUTE_RESPONSE "Error: Failed to compute SAKE response\n"
#define ERR_SEND_RESPONSE "Error: Failed to send response\n"
#define ERR_RECEIVE_CLIENT_NONCE "Error: Failed to receive client nonce\n"
#define ERR_SEND_CHALLENGE "Error: Failed to send challenge\n"
#define ERR_RECEIVE_RESPONSE "Error: Failed to receive response\n"
#define ERR_CLIENT_AUTH_FAILED "Error: Client authentication failed\n"
#define ERR_AUTH_VERIFICATION "Error: Failed to verify authentication result\n"
#define ERR_AUTH_FAILED "Error: Authentication failed - incorrect master key\n"
#define ERR_AUTH_CONFIRMATION "Error: Failed to send authentication confirmation\n"
#define ERR_SAKE_MITM_SUSPECTED_SERVER "Error: SAKE authentication failed. Potential Man-in-the-Middle attack suspected or incorrect password.\n"
#define ERR_SAKE_MITM_SUSPECTED_CLIENT "Error: SAKE authentication failed by server. Potential Man-in-the-Middle attack suspected or incorrect password.\n"

// Chybove spravy pre spracovanie blokov
#define ERR_RECEIVE_ENCRYPTED_CHUNK "Error: Failed to receive encrypted chunk\n"
#define ERR_DECRYPT_CHUNK_AUTH "Error: Failed to decrypt chunk (authentication failed)\n"
#define ERR_WRITE_TO_FILE "Error: Failed to write to file\n"

#endif // ERRORS_H
