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

// Helper functions for reliable data transmission
ssize_t send_all(int sock, const void *buf, size_t size);
ssize_t recv_all(int sock, void *buf, size_t size);

// Helper functions for reliable chunk size transmission 
int send_chunk_size_reliable(int socket, uint32_t size);
int receive_chunk_size_reliable(int socket, uint32_t *size);

// Serverove funkcie
// Funkcie potrebne pre vytvorenie a spravu serverovej casti
int setup_server(void);                 // Vytvori a nakonfiguruje server socket
int accept_client_connection(int server_fd, struct sockaddr_in *client_addr);  // Prijme spojenie od klienta
int send_ready_signal(int socket);      // Posle signal pripravenosti klientovi
int receive_salt(int socket, uint8_t *salt);  // Prijme kryptograficku sol
int send_key_acknowledgment(int socket);  // Posle potvrdenie o prijati kluca

// Klientske funkcie
// Funkcie potrebne pre vytvorenie a spravu klientskej casti
int connect_to_server(const char *address);  // Pripoji sa k serveru
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