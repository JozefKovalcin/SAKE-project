/********************************************************************************
 * Program:    Implementacia sietovych funkcii pre zabezpeceny prenos s SAKE
 * Subor:      siete.c
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      05-03-2025
 * 
 * Popis: 
 *     Implementacia sietovych funkcii pre zabezpeceny prenos:
 *     - Podporu pre protokol SAKE (Symmetric Authenticated Key Exchange)
 *     - Inicializacia a sprava sietovych spojeni
 *     - Spolahlivy prenos dat a synchronizacia
 *     - Platformovo-nezavisle sietove operacie (Windows/Linux)
 *     - Obsluha timeoutov a chybovych stavov
 *     - Implementacia potvrdzovacieho protokolu pre spolahlivy prenos
 * 
 * Zavislosti:
 *     - siete.h (deklaracie sietovych funkcii)
 *     - constants.h (definicie konstant pre program)
 *     - platform.h (platform-specificke funkcie)
 *******************************************************************************/

#include <stdio.h>        // Kniznica pre standardny vstup a vystup
#include <stdlib.h>       // Kniznica pre vseobecne funkcie
#include <string.h>       // Kniznica pre pracu s retazcami
#include <errno.h>        // Kniznica pre systemove chyby

#include "siete.h"        // Pre sietove funkcie
#include "constants.h"    // Definicie konstant pre program
#include "platform.h"     // Pre funkcie specificke pre operacny system

// Implementacia funkcii pre spravu socketov
// Rozdielna implementacia pre Windows a Linux

// Uvolnenie Winsock pre Windows platformu
void cleanup_network(void) {
    NETWORK_CLEANUP();
}

// Bezpecne zatvorenie socketu
void cleanup_socket(int sock) {
    SOCKET_CLOSE(sock);
}

// Zatvorenie oboch socketov (klient + server)
// Pouzivane pri ukonceni spojenia alebo chybe
void cleanup_sockets(int new_socket, int server_fd) {
    SOCKET_CLOSE(new_socket);
    SOCKET_CLOSE(server_fd);
}

// Inicializacia sietovej kniznice pre Windows
// Na Linuxe nie je potrebna
void initialize_network(void) {
    NETWORK_INIT();
}

// Bezpecne ukoncenie socketu
// Zaistuje korektne ukoncenie spojenia
void shutdown_socket(int sock) {
    SOCKET_SHUTDOWN(sock);
}

// Cakacia funkcia s platformovo nezavislou implementaciou
void wait(void) {
    WAIT_MS(WAIT_DELAY_MS);
}

// Nastavenie timeoutov pre socket
// Zaistuje, ze operacie nebudu blokovat program donekonecna
void set_timeout_options(int sock) {
    SET_SOCKET_TIMEOUT(sock, SOCKET_TIMEOUT_MS);
    SET_KEEPALIVE(sock);
}

// Serverove funkcie

// Vytvorenie a konfiguracia servera
// - Vytvori socket
// - Nastavi adresu a port
// - Zacne pocuvat na porte
int setup_server(int port) {
    // Server socket, ktory pocuva na urcitej adrese
    int server_fd;
    // Struktura address obsahuje informacie o tom, kde ma server pocuvat
    struct sockaddr_in address;

    // Vytvorenie novej "schranky" (socketu)
    // AF_INET znamena ze pouzivame IPv4 adresy
    // SOCK_STREAM znamena ze chceme spolahlivy prenos (TCP)
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, ERR_SOCKET_CREATE);
        return -1;
    }

    // Nastavenie adresy servera:
    // - sin_family: pouzivame IPv4
    // - sin_addr.s_addr: server bude pocuvat na vsetkych dostupnych adresach
    // - sin_port: cislo portu, na ktorom bude server pocuvat
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;   // 0.0.0.0 - vsetky dostupne adresy
    address.sin_port = htons(port);         // Prevedieme cislo portu do sietoveho formatu

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fprintf(stderr, ERR_SOCKET_BIND, strerror(errno));
        return -1;
    }

    if (listen(server_fd, MAX_PENDING_CONNECTIONS) < 0) {
        fprintf(stderr, ERR_SOCKET_LISTEN, strerror(errno));
        return -1;
    }

    return server_fd;
}

// Prijatie spojenia od klienta
// - Prijme prichadzajuce spojenie
// - Vypise informacie o klientovi
int accept_client_connection(int server_fd, struct sockaddr_in *client_addr) {
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int new_socket = accept(server_fd, (struct sockaddr *)client_addr, &addrlen);
    
    if (new_socket < 0) {
        fprintf(stderr, ERR_SOCKET_ACCEPT);
        return -1;
    }
    
    // Nastavenie pre formatovanie IP adresy zo sietoveho formatu do textoveho
    // Priklad: Z binarneho formatu vytvori retazec "192.168.1.1"
    printf(MSG_CONNECTION_ACCEPTED, 
           inet_ntoa(client_addr->sin_addr),  // Prevedie IP adresu na citatelny text
           ntohs(client_addr->sin_port));     // Prevedie cislo portu zo sietoveho formatu
    
    return new_socket;
}

// Funkcie pre prenos dat

// Odoslanie signalu pripravenosti klientovi
int send_ready_signal(int socket) {
    if (send(socket, MAGIC_READY, SIGNAL_SIZE, 0) != SIGNAL_SIZE) {
        fprintf(stderr, ERR_READY_SIGNAL);
        return -1;
    }
    return 0;
}

// Vytvorenie spojenia so serverom
// - Vytvori socket
// - Pripoji sa na zadanu adresu
int connect_to_server(const char *address, int port) {
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, ERR_SOCKET_CREATE);
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, address, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, ERR_INVALID_ADDRESS);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, ERR_CONNECTION_FAILED);
        return -1;
    }

    return sock;
}

// Funkcie pre prenos kryptografickych materialov

// Prijatie kryptografickej soli od klienta
int receive_salt(int socket, uint8_t *salt) {
    return (RECV_DATA(socket, salt, SALT_SIZE) == SALT_SIZE) ? 0 : -1;
}

// Odoslanie kryptografickej soli serveru
int send_salt_to_server(int socket, const uint8_t *salt) {
    return (send(socket, (const char *)salt, SALT_SIZE, 0) == SALT_SIZE) ? 0 : -1;
}

// Funkcie pre synchronizaciu

// Cakanie na signal pripravenosti
int wait_for_ready(int socket) {
    char buffer[SIGNAL_SIZE + 1] = {0};
    if (recv(socket, buffer, SIGNAL_SIZE, 0) <= 0 || strcmp(buffer, MAGIC_READY) != 0) {
        fprintf(stderr, ERR_READY_RECEIVE);
        return -1;
    }
    return 0;
}

// Funkcia caka na potvrdenie uspesneho prijatia kluca od servera
// - Skontroluje ci prijaty signal ma spravnu velkost a spravny obsah
int wait_for_key_acknowledgment(int socket) {
    char buffer[SIGNAL_SIZE + 1] = {0};
    int received = recv(socket, buffer, SIGNAL_SIZE, MSG_WAITALL);
    if (received != SIGNAL_SIZE) {
        fprintf(stderr, ERR_KEY_ACK_RECEIVE, received);
        return -1;
    }
    if (memcmp(buffer, MAGIC_KEYOK, SIGNAL_SIZE) != 0) {
        fprintf(stderr, ERR_KEY_ACK_INVALID, received, buffer);
        return -1;
    }
    printf(MSG_KEY_ACK_RECEIVED);
    return 0;
}

// Funkcia posle potvrdenie uspesneho prijatia kluca
int send_key_acknowledgment(int socket) {
    int result = send(socket, MAGIC_KEYOK, SIGNAL_SIZE, 0);
    if (result != SIGNAL_SIZE) {
        fprintf(stderr, ERR_KEY_ACK_SEND, result);
        return -1;
    }
    return 0;
}

// Nastavi timeout pre socket operacie
// - timeout_ms: cas v milisekundach
void set_socket_timeout(int socket, int timeout_ms) {
    SET_SOCKET_TIMEOUT(socket, timeout_ms);
}

// Vypne TCP bufferovanie pre okamzite odosielanie dat
static void disable_tcp_buffering(int socket) {
    DISABLE_TCP_BUFFERING(socket);
}

// Posle synchronizacny signal a caka na jeho potvrdenie
// - Zabezpecuje, ze spojenie je funkcne a synchronizovane
int send_session_sync(int socket) {
    disable_tcp_buffering(socket);
    // Posle presne 4 byty synchronizacneho signalu
    if (send(socket, SESSION_SYNC_MAGIC, SESSION_SYNC_SIZE, MSG_NOSIGNAL) != SESSION_SYNC_SIZE) {
        fprintf(stderr, ERR_SYNC_SEND);
        return -1;
    }
    
    // Caka na echo tych istych 4 bytov
    char ack[SESSION_SYNC_SIZE];
    if (recv(socket, ack, SESSION_SYNC_SIZE, MSG_WAITALL) != SESSION_SYNC_SIZE ||
        memcmp(ack, SESSION_SYNC_MAGIC, SESSION_SYNC_SIZE) != 0) {
        fprintf(stderr, ERR_SYNC_INVALID);
        return -1;
    }
    
    return 0;
}

// Caka na synchronizacny signal a posiela jeho potvrdenie
int wait_for_session_sync(int socket) {
    disable_tcp_buffering(socket);
    
    // Precita presne 4 byty synchronizacneho signalu
    char sync[SESSION_SYNC_SIZE];
    if (recv(socket, sync, SESSION_SYNC_SIZE, MSG_WAITALL) != SESSION_SYNC_SIZE ||
        memcmp(sync, SESSION_SYNC_MAGIC, SESSION_SYNC_SIZE) != 0) {
        fprintf(stderr, ERR_SYNC_MESSAGE);
        return -1;
    }
    
    // Posle naspat tie iste 4 byty ako potvrdenie
    if (send(socket, sync, SESSION_SYNC_SIZE, MSG_NOSIGNAL) != SESSION_SYNC_SIZE) {
        fprintf(stderr, ERR_SYNC_ACK_SEND);
        return -1;
    }
    
    return 0;
}

// Posle nazov suboru prijemcovi
int send_file_name(int socket, const char *file_name) {
    return (send(socket, file_name, strlen(file_name) + 1, 0) > 0) ? 0 : -1;
}

// Prijme nazov suboru od odosielatela
// - max_len: maximalna velkost buffera pre nazov suboru
int receive_file_name(int socket, char *file_name, size_t max_len) {
    memset(file_name, 0, max_len);
    size_t total_received = 0;
    while (total_received < max_len) {
        ssize_t received = recv(socket, file_name + total_received, max_len - total_received, 0);
        if (received <= 0) {
            return -1;
        }
        total_received += received;
        if (file_name[total_received - 1] == '\0') {
            break;
        }
    }
    return 0;
}

// Posle velkost datoveho bloku v sietovom poradi bytov
int send_chunk_size_reliable(int socket, uint32_t size) {
    uint32_t net_size = htonl(size);
    return (send_all(socket, &net_size, sizeof(net_size)) == sizeof(net_size)) ? 0 : -1;
}

// Prijme velkost datoveho bloku a prevedie ju do lokalneho poradia bytov
int receive_chunk_size_reliable(int socket, uint32_t *size) {
    uint32_t net_size;
    if (recv_all(socket, &net_size, sizeof(net_size)) != sizeof(net_size)) {
        return -1;
    }
    *size = ntohl(net_size);
    return 0;
}

// Pomocna funkcia na spolahlivy prenos vsetkych dat
// - Garantuje odoslanie vsetkych dat alebo chybu
ssize_t send_all(int sock, const void *buf, size_t size) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t remaining = size;
    
    while (remaining > 0) {
        ssize_t sent = send(sock, (const char*)p, remaining, SEND_FLAGS);
        if (sent <= 0) {
            if (errno == EINTR) continue;  // Prerusenie, skusi znova
            return -1;  // Chyba
        }
        p += sent;
        remaining -= sent;
    }
    return size;
}

// Pomocna funkcia na spolahlivy prijem vsetkych dat
// - Garantuje prijem vsetkych dat alebo chybu
ssize_t recv_all(int sock, void *buf, size_t size) {
    uint8_t *p = (uint8_t *)buf;
    size_t remaining = size;
    
    while (remaining > 0) {
        ssize_t received = recv(sock, (char*)p, remaining, MSG_WAITALL);
        if (received <= 0) {
            if (errno == EINTR) continue;  // Prerusenie, skusi znova
            return -1;  // Chyba alebo ukoncene spojenie
        }
        p += received;
        remaining -= received;
    }
    return size;
}

// Posle zasifrovany blok dat spolu s noncom a tagom
int send_encrypted_chunk(int socket, const uint8_t *nonce, const uint8_t *tag,
                        const uint8_t *data, size_t data_len)
{
    if (send_all(socket, nonce, NONCE_SIZE) != NONCE_SIZE ||
        send_all(socket, tag, TAG_SIZE) != TAG_SIZE ||
        send_all(socket, data, data_len) != (ssize_t)data_len) {
        return -1;
    }
    return 0;
}

// Prijme zasifrovany blok dat spolu s noncom a tagom
int receive_encrypted_chunk(int sockfd, uint8_t *nonce, uint8_t *tag,
                          uint8_t *ciphertext, uint32_t chunk_size)
{
    // Odstrani debug vystup pre zjednodusenie konzoly
    
    if (recv_all(sockfd, nonce, NONCE_SIZE) != NONCE_SIZE) {
        fprintf(stderr, ERR_RECEIVE_ENCRYPTED_CHUNK);
        return -1;
    }
    
    if (recv_all(sockfd, tag, TAG_SIZE) != TAG_SIZE) {
        fprintf(stderr, "Error: Failed to receive tag\n");
        return -1;
    }
    
    if (chunk_size > 0 && recv_all(sockfd, ciphertext, chunk_size) != (ssize_t)chunk_size) {
        fprintf(stderr, "Error: Failed to receive ciphertext (expected %u bytes)\n", chunk_size);
        return -1;
    }
    
    return 0;
}

// Posle potvrdenie uspesneho prenosu s opakovaniami
int send_transfer_ack(int socket) {
    int retries = MAX_RETRIES;
    
    while (retries > 0) {
        printf(MSG_ACK_SENDING, MAX_RETRIES - retries + 1, MAX_RETRIES);
        
        int result = send(socket, MAGIC_TACK, ACK_SIZE, SEND_FLAGS);
        
        if (result == ACK_SIZE) {
            wait();
            return 0;
        }
        
        retries--;
        if (retries > 0) {
            printf(MSG_ACK_RETRY, WAIT_DELAY_MS);
            wait();
        }
    }
    return -1;
}

// Caka na potvrdenie uspesneho prenosu s opakovaniami
int wait_for_transfer_ack(int socket) {
    int retries = MAX_RETRIES;
    char ack_buffer[ACK_SIZE + 1] = {0};
    
    while (retries > 0) {
        printf(MSG_ACK_WAITING, MAX_RETRIES - retries + 1, MAX_RETRIES);
        
        int received = recv(socket, ack_buffer, ACK_SIZE, MSG_WAITALL);
        
        if (received == ACK_SIZE && memcmp(ack_buffer, MAGIC_TACK, ACK_SIZE) == 0) {
            return 0;
        }
        
        retries--;
        if (retries > 0) {
            printf(MSG_ACK_RETRY_RECEIVE, received, WAIT_DELAY_MS);
            wait();
        }
    }
    return -1;
}