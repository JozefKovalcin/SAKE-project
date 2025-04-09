/********************************************************************************
 * Program:    Sietova komunikacia pre zabezpeceny prenos s protokolom SAKE
 * Subor:      siete.h
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      05-03-2025
 * 
 * Popis: 
 *     Hlavickovy subor pre sietovu komunikaciu:
 *     - Podporu pre protokol SAKE (Symmetric Authenticated Key Exchange)
 *     - Inicializacia a sprava sietovych spojeni
 *     - Spolahlivy prenos dat a synchronizacia
 *     - Platformovo-nezavisle sietove operacie
 *     - Obsluha timeoutov a chybovych stavov
 *     - Implementacia potvrdzovacieho protokolu
 * 
 * Zavislosti:
 *     - Standardne C kniznice pre sietovu komunikaciu
 *     - constants.h (konstanty programu)
 *     - platform.h (platform-specificke funkcie)
 *******************************************************************************/

#ifndef SIETE_H
#define SIETE_H

#include <stdint.h> // Kniznica pre datove typy (uint8_t, uint32_t)

#include "constants.h"    // Definicie konstant pre program
#include "platform.h"     // Pre funkcie specificke pre operacny system

// Platformovo-specificke makra
#ifdef _WIN32
    // Funkcie pre uvolnenie socketov - Windows verzie
    #define SOCKET_CLOSE(sock) closesocket(sock)          // Uzatvori socket na Windows
    #define NETWORK_CLEANUP() WSACleanup()                // Uvolni Winsock API
    #define NETWORK_INIT() do { \
        WSADATA wsaData; \
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) { \
            fprintf(stderr, ERR_WINSOCK_INIT); \
            exit(-1); \
        } \
    } while(0)                                            // Inicializuje Winsock API
    
    // Nastavenia socketov a timeouty pre Windows
    #define SET_SOCKET_TIMEOUT(sock, timeout_val) do { \
        DWORD timeout = (timeout_val); \
        setsockopt((sock), SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)); \
        setsockopt((sock), SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)); \
    } while(0)                                            // Nastavi casove limity pre socket
    
    #define SET_KEEPALIVE(sock) do { \
        BOOL keepalive = TRUE; \
        setsockopt((sock), SOL_SOCKET, SO_KEEPALIVE, (char*)&keepalive, sizeof(keepalive)); \
    } while(0)                                            // Zapne udrzovanie spojenia (keepalive)
    
    // Operacie pre ukoncenie a cakanie - Windows
    #define SOCKET_SHUTDOWN(sock) do { \
        shutdown((sock), SD_BOTH); \
        Sleep(SOCKET_SHUTDOWN_DELAY_MS); \
    } while(0)                                            // Bezpecne ukonci spojenie na sockete
    
    #define WAIT_MS(ms) Sleep(ms)                         // Pozastavi vykonavanie na dany cas v ms
    
    // Sprava TCP buffera - Windows
    #define DISABLE_TCP_BUFFERING(sock) do { \
        int flag = 1; \
        setsockopt((sock), IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag)); \
    } while(0)                                            // Vypne Nagleho algoritmus - okamzite odosielanie
    
    // Prenos dat - Windows
    #define SEND_FLAGS 0                                  // Ziadne specialne flagy pre Windows
    #define RECV_DATA(sock, data, size) recv((sock), (char*)(data), (size), 0)  // Prijatie dat na Windows
#else
    // Funkcie pre uvolnenie socketov - UNIX/Linux verzie
    #define SOCKET_CLOSE(sock) close(sock)                // Uzatvori socket na UNIX systemoch
    #define NETWORK_CLEANUP() ((void)0)                   // Prazdna operacia - Linux nevyzaduje cistenie
    #define NETWORK_INIT() ((void)0)                      // Prazdna operacia - Linux nevyzaduje inicializaciu
    
    // Nastavenia socketov a timeouty pre UNIX/Linux
    #define SET_SOCKET_TIMEOUT(sock, timeout_val) do { \
        struct timeval timeout; \
        timeout.tv_sec = (timeout_val) / 1000; \
        timeout.tv_usec = ((timeout_val) % 1000) * 1000; \
        setsockopt((sock), SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)); \
        setsockopt((sock), SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)); \
    } while(0)                                            // Nastavi casove limity pre socket
    
    #define SET_KEEPALIVE(sock) do { \
        int keepalive = 1; \
        setsockopt((sock), SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)); \
    } while(0)                                            // Zapne udrzovanie spojenia (keepalive)
    
    // Operacie pre ukoncenie a cakanie - UNIX/Linux
    #define SOCKET_SHUTDOWN(sock) do { \
        shutdown((sock), SHUT_RDWR); \
        sleep(SOCKET_SHUTDOWN_DELAY_MS / 1000); \
    } while(0)                                            // Bezpecne ukonci spojenie na sockete
    
    #define WAIT_MS(ms) usleep((ms) * 1000)               // Pozastavi vykonavanie na dany cas v ms
    
    // Sprava TCP buffera - UNIX/Linux
    #define DISABLE_TCP_BUFFERING(sock) do { \
        int flag = 1; \
        setsockopt((sock), IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)); \
    } while(0)                                            // Vypne Nagleho algoritmus - okamzite odosielanie
    
    // Prenos dat - UNIX/Linux
    #define SEND_FLAGS MSG_NOSIGNAL                       // Zabrani vzniku SIGPIPE signalu pri zavreti spojenia
    #define RECV_DATA(sock, data, size) read((sock), (data), (size))  // Prijatie dat na UNIX systemoch
#endif

// Zakladne sietove funkcie
// Funkcie pre spravu socketov a inicializaciu siete
void cleanup_socket(int sock);           // Uvolni jeden socket
void cleanup_sockets(int new_socket, int server_fd);  // Uvolni dva sockety
void initialize_network(void);          // Inicializacia Winsock pre Windows
void shutdown_socket(int sock);          // Bezpecne ukoncenie socketu
void wait(void);                        // Cakacia funkcia pre synchronizaciu
void set_timeout_options(int sock);      // Nastavenie timeoutu pre socket
void cleanup_network(void);             // Ukoncenie Winsock pre Windows
void set_socket_timeout(int sock, int timeout_ms);  // Nastavenie timeoutu pre socket

// Pomocne funkcie pre prenos dat
ssize_t send_all(int sock, const void *buf, size_t size);
ssize_t recv_all(int sock, void *buf, size_t size);

// Pomocne funkcie pre spravu chunkov
int send_chunk_size_reliable(int socket, uint32_t size);
int receive_chunk_size_reliable(int socket, uint32_t *size);

// Serverove funkcie
// Funkcie potrebne pre vytvorenie a spravu serverovej casti
int setup_server(int port);             // Vytvori a nakonfiguruje server socket na danom porte
int accept_client_connection(int server_fd, struct sockaddr_in *client_addr);  // Prijme spojenie od klienta
int send_ready_signal(int socket);      // Posle signal pripravenosti klientovi
int receive_salt(int socket, uint8_t *salt);  // Prijme kryptograficku sol
int send_key_acknowledgment(int socket);  // Posle potvrdenie o prijati kluca

// Klientske funkcie
// Funkcie potrebne pre vytvorenie a spravu klientskej casti
int connect_to_server(const char *address, int port);  // Pripoji sa k serveru na danom porte
int wait_for_ready(int socket);          // Caka na signal pripravenosti
int send_salt_to_server(int socket, const uint8_t *salt);  // Posle sol serveru
int wait_for_key_acknowledgment(int socket);  // Caka na potvrdenie kluca

// Funkcie pre prenos suborov
// Zdielane funkcie pre prenos zasifrovanych dat
int send_file_name(int socket, const char *file_name);      // Posle nazov suboru
int receive_file_name(int socket, char *file_name, size_t max_len);  // Prijme nazov suboru
int send_encrypted_chunk(int socket, const uint8_t *nonce, const uint8_t *tag,  // Posle zasifrovany blok
                        const uint8_t *data, size_t data_len);

                        
int receive_encrypted_chunk(int sockfd, uint8_t *nonce, uint8_t *tag,
                          uint8_t *ciphertext, uint32_t chunk_size); // Prijme zasifrovany blok
int send_transfer_ack(int socket);       // Posle potvrdenie o prenose
int wait_for_transfer_ack(int socket);   // Caka na potvrdenie o prenose

// Funkcie pre synchronizaciu
int send_session_sync(int socket); // Posle synchronizacnu spravu
int wait_for_session_sync(int socket); // Caka na synchronizacnu spravu

#endif // SIETE_H