/********************************************************************************
 * Program:    Server pre zabezpeceny prenos suborov s protokolom SAKE
 * Subor:      server.c
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      05-03-2025
 *
 * Popis:
 *     Implementacia servera pre zabezpeceny prenos suborov. Program zabezpecuje:
 *     - Vytvorenie TCP servera a prijimanie spojeni
 *     - Autentizaciu pomocou SAKE protokolu (Symmetric Authenticated Key Exchange)
 *     - Bezpecnu vymenu klucov s klientom zalozenu na zdielanom tajomstve
 *     - Prijimanie a desifrovanie suborov pomocou ChaCha20-Poly1305
 *     - Overovanie integrity prijatych dat cez Poly1305 MAC
 *     - Podporu pravidelnej rotacie klucov pocas prenosu
 *     - Dopredna ochrana pomocou jednosmernych hashovacich funkcii
 *
 * Zavislosti:
 *     - Monocypher 4.0.2 (sifrovacie algoritmy)
 *     - siete.h (sietova komunikacia)
 *     - crypto_utils.h (kryptograficke operacie)
 *     - constants.h (konstanty programu)
 *     - sake.h (pre SAKE protokol)
 *     - platform.h (platform-specificke funkcie)
 *******************************************************************************/

// Systemove kniznice
#include <stdio.h>  // Kniznica pre standardny vstup a vystup (nacitanie zo suborov, vypis na obrazovku)
#include <stdlib.h> // Kniznica pre vseobecne funkcie (sprava pamate, konverzie, nahodne cisla)
#include <string.h> // Kniznica pre pracu s retazcami (kopirovanie, porovnavanie, spajanie)
#include <unistd.h> // Kniznica pre systemove volania UNIX (procesy, subory, sokety)

#include "monocypher.h"   // Pre Monocypher kryptograficke funkcie
#include "siete.h"        // Pre sietove funkcie
#include "constants.h"    // Definicie konstant pre program
#include "crypto_utils.h" // Pre kryptograficke funkcie
#include "sake.h"         // Pre SAKE protokol
#include "platform.h"     // Pre funkcie specificke pre operacny system

// Globalne premenne pre kryptograficke operacie
// Tieto premenne sa pouzivaju v celom programe pre desifrovacie operacie
uint8_t key[KEY_SIZE];      // Hlavny sifrovaci kluc
uint8_t nonce[NONCE_SIZE];  // Jednorazova hodnota pre kazdy blok
uint8_t salt[SALT_SIZE];    // Sol pre derivaciu kluca
sake_key_chain_t key_chain; // Struktura retazca klucov pre SAKE

int main()
{
    // Inicializacia sietovych prvkov
    int server_fd, client_socket;
    struct sockaddr_in client_addr;
    int port;
    char port_str[6]; // Max 5 cislic + null terminator

    // Inicializacia Winsock pre Windows platformu
    initialize_network();

    // Ziadanie cisla portu od uzivatela
    printf(PORT_PROMPT);
    if (fgets(port_str, sizeof(port_str), stdin) == NULL)
    {
        fprintf(stderr, ERR_PORT_READ);
        cleanup_network();
        return -1;
    }

    // Konverzia portu na integer a validacia
    char *endptr;
    long port_long = strtol(port_str, &endptr, 10);
    if (endptr == port_str || *endptr != '\n' || port_long < 1 || port_long > 65535)
    {
        fprintf(stderr, ERR_PORT_INVALID);
        cleanup_network();
        return -1;
    }
    port = (int)port_long;

    // Vytvorenie a konfiguracia servera
    if ((server_fd = setup_server(port)) < 0)
    {
        // Vypis chyby, ak sa nepodari nastavit serverovy socket
        fprintf(stderr, ERR_SOCKET_SETUP, port, strerror(errno));
        cleanup_network();
        return -1;
    }

    printf(LOG_SERVER_START, port);

    // Cakanie na pripojenie klienta
    if ((client_socket = accept_client_connection(server_fd, &client_addr)) < 0)
    {
        // Vypis chyby, ak sa nepodari prijat klientske spojenie
        fprintf(stderr, ERR_CLIENT_ACCEPT, strerror(errno));
        cleanup_sockets(-1, server_fd); // Upratanie serveroveho socketu
        cleanup_network();
        return -1;
    }
    
    // Inicializacia bezpecneho spojenia
    if (send_ready_signal(client_socket) < 0)
    {
        // Vypis chyby, ak zlyha odoslanie signalu pripravenosti
        fprintf(stderr, ERR_HANDSHAKE);
        cleanup_sockets(client_socket, server_fd);
        cleanup_network();
        return -1;
    }

    // Prijatie soli od klienta
    uint8_t salt[SALT_SIZE];
    if (receive_salt(client_socket, salt) < 0)
    {
        fprintf(stderr, ERR_SALT_RECEIVE);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Nacitanie hesla od uzivatela a odvodenie hlavneho kluca pomocou Argon2
    // Heslo sa pouzije na generovanie kluca, ktory sa pouzije na sifrovanie dat
    char *password = platform_getpass(PASSWORD_PROMPT);
    if (derive_key_server(password, salt, key, salt) != 0)
    {
        fprintf(stderr, ERR_KEY_DERIVATION);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Odoslanie potvrdenia kluca klientovi
    if (send_key_acknowledgment(client_socket) < 0)
    {
        fprintf(stderr, ERR_KEY_ACK);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // SAKE protokol - implementacia
    uint8_t client_nonce[SAKE_NONCE_CLIENT_SIZE]; // Nonce vygenerované klientom
    uint8_t server_nonce[SAKE_NONCE_SERVER_SIZE]; // Nonce prijate od servera
    uint8_t challenge[SAKE_CHALLENGE_SIZE];       // VYzva prijata od servera
    uint8_t response[SAKE_RESPONSE_SIZE];         // Odpoved vypocitana na vyzvu
    uint8_t session_key[SESSION_KEY_SIZE];        // Kluc relacie

    // Inicializacia SAKE key chain pre server (responder)
    // Odvodi authentication key z master key
    sake_init_key_chain(&key_chain, key, 0); // 0 = responder

    // Prijatie nonce od klienta
    if (recv_all(client_socket, client_nonce, SAKE_NONCE_CLIENT_SIZE) != SAKE_NONCE_CLIENT_SIZE)
    {
        fprintf(stderr, ERR_RECEIVE_CLIENT_NONCE);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Generovanie vyzvy a nonce servera - pouzivame aktualny authentication key
    generate_challenge(challenge, server_nonce, key_chain.auth_key_curr, client_nonce);

    // Odoslanie nonce servera a vyzvy klientovi
    if (send_all(client_socket, server_nonce, SAKE_NONCE_SERVER_SIZE) != SAKE_NONCE_SERVER_SIZE ||
        send_all(client_socket, challenge, SAKE_CHALLENGE_SIZE) != SAKE_CHALLENGE_SIZE)
    {
        fprintf(stderr, ERR_SEND_CHALLENGE);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Prijatie odpovede od klienta
    if (recv_all(client_socket, response, SAKE_RESPONSE_SIZE) != SAKE_RESPONSE_SIZE)
    {
        fprintf(stderr, ERR_RECEIVE_RESPONSE);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Overenie odpovede - pouzivame aktualny authentication key
    if (verify_response(response, key_chain.auth_key_curr, challenge, server_nonce) != 0)
    {
        // Vypis specifickejsej chybovej hlasky pri zlyhani overenia
        // Naznacuje mozne nespravne heslo alebo MitM utok
        fprintf(stderr, ERR_SAKE_MITM_SUSPECTED_SERVER);

        // Odoslanie klientovi informacie o zlyhani autentizacie
        uint8_t auth_result = AUTH_FAILED;
        send_all(client_socket, &auth_result, 1); // Ignorujeme navratovu hodnotu, spojenie sa aj tak ukonci

        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Odoslanie klientovi potvrdenia o uspesnej autentizacii
    uint8_t auth_result = AUTH_SUCCESS;
    if (send_all(client_socket, &auth_result, 1) != 1)
    {
        fprintf(stderr, ERR_AUTH_CONFIRMATION);
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Odvodenie kluca relacie z hlavneho kluca
    derive_session_key(session_key, key_chain.master_key, client_nonce, server_nonce);

    // Evolucia klucov po uspesnej autentizacii
    sake_update_key_chain(&key_chain);

    printf(LOG_SESSION_COMPLETE);

    // Nastavenie casovaceho limitu pre prijem nazvu suboru
    set_socket_timeout(client_socket, WAIT_FILE_NAME);

    char file_name[FILE_NAME_BUFFER_SIZE];
    if (receive_file_name(client_socket, file_name, sizeof(file_name)) < 0)
    {
        fprintf(stderr, ERR_FILENAME_RECEIVE, strerror(errno));
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Resetovanie casovaceho limitu na mensiu hodnotu pre prenos dat
    set_socket_timeout(client_socket, SOCKET_TIMEOUT_MS);

    // Spracovanie novo prijateho suboru
    // Vytvorenie noveho nazvu suboru pridanim predpony 'received_'
    char new_file_name[NEW_FILE_NAME_BUFFER_SIZE];
    snprintf(new_file_name, sizeof(new_file_name), "%s%s", FILE_PREFIX, file_name);

    // Otvorenie noveho suboru pre binarny zapis
    // Kontrola uspesnosti vytvorenia suboru
    FILE *file = fopen(new_file_name, FILE_MODE_WRITE);
    if (!file)
    {
        fprintf(stderr, ERR_FILE_CREATE, new_file_name, strerror(errno));
        cleanup_sockets(client_socket, server_fd);
        return -1;
    }

    // Inicializacia premennych pre sledovanie prenosu
    uint64_t total_bytes = 0;  // Celkovy pocet prijatych bajtov
    int transfer_complete = 0; // Stav prenosu (0 = prebieha, 1 = uspesne dokonceny, -1 = chyba)

    printf(LOG_TRANSFER_START);

    // Buffery pre prenos dat
    // ciphertext: Zasifrovane data z klienta
    // plaintext: Desifrovane data pre zapis
    // tag: Autentizacny tag pre overenie integrity
    uint8_t ciphertext[TRANSFER_BUFFER_SIZE]; // Buffer pre zasifrovane data
    uint8_t plaintext[TRANSFER_BUFFER_SIZE];  // Buffer pre desifrovane data
    uint8_t tag[TAG_SIZE];                    // Buffer pre autentizacny tag

    // Prenos suboru s rotaciou klucov
    uint64_t block_count = 0;
    uint8_t buffer[TRANSFER_BUFFER_SIZE];

    // Premenna pre sledovanie postupu
    uint64_t last_progress_update = 0;

    // Hlavny cyklus prenosu dat
    while (!transfer_complete)
    {
        uint32_t chunk_size;
        if (receive_chunk_size_reliable(client_socket, &chunk_size) < 0)
        {
            fprintf(stderr, ERR_CHUNK_SIZE);
            transfer_complete = -1;
            break;
        }

        // Overeenie, ci je prijaty blok velkosti 0, co znamena koniec suboru (EOF)
        if (chunk_size == 0)
        {
            printf("\n");
            printf(LOG_TRANSFER_COMPLETE);
            if (send_transfer_ack(client_socket) == 0)
            {
                transfer_complete = 1;
            }
            break;
        }

        // Spracovanie markera rotacie kluca
        if (chunk_size == KEY_ROTATION_MARKER)
        {
            printf(MSG_KEY_ROTATION, (unsigned long long)block_count);

            if (send_chunk_size_reliable(client_socket, KEY_ROTATION_ACK) < 0)
            {
                fprintf(stderr, ERR_KEY_ROTATION_ACK);
                transfer_complete = -1;
                break;
            }

            // Prijatie noveho client nonce
            uint8_t new_client_nonce[SAKE_NONCE_CLIENT_SIZE];
            if (recv_all(client_socket, new_client_nonce, SAKE_NONCE_CLIENT_SIZE) != SAKE_NONCE_CLIENT_SIZE)
            {
                fprintf(stderr, "Error: Failed to receive new client nonce\n");
                transfer_complete = -1;
                break;
            }

            // Generovanie noveho server nonce
            uint8_t new_server_nonce[SAKE_NONCE_SERVER_SIZE];
            generate_random_bytes(new_server_nonce, SAKE_NONCE_SERVER_SIZE);

            // Odosielanie noveho server nonce
            if (send_all(client_socket, new_server_nonce, SAKE_NONCE_SERVER_SIZE) != SAKE_NONCE_SERVER_SIZE)
            {
                fprintf(stderr, "Error: Failed to send new server nonce\n");
                transfer_complete = -1;
                break;
            }

            // Validacia rotacie kluca
            uint32_t signal;
            // Prijatie signalu pre validaciu rotacie kluca od klienta
            if (receive_chunk_size_reliable(client_socket, &signal) < 0 ||
                signal != KEY_ROTATION_VALIDATE)
            {
                fprintf(stderr, ERR_KEY_VALIDATE_SIGNAL);
                transfer_complete = -1;
                break;
            }

            uint8_t previous_session_key[KEY_SIZE];
            // Zalohovanie aktualneho kluca pred rotaciou
            memcpy(previous_session_key, session_key, KEY_SIZE);

            // Pre session key pouzivame aktualizovany master key a nove nonce hodnoty
            derive_session_key(session_key, key_chain.master_key, new_client_nonce, new_server_nonce);

            // Aktualizacia client_nonce a server_nonce pre ďalšie pouzitie
            memcpy(client_nonce, new_client_nonce, SAKE_NONCE_CLIENT_SIZE);
            memcpy(server_nonce, new_server_nonce, SAKE_NONCE_SERVER_SIZE);

            // Kontrola validacie kluca
            uint8_t client_validation[VALIDATION_SIZE];
            uint8_t our_validation[VALIDATION_SIZE];

            // Prijatie validacneho kodu od klienta, ktory bol vytvoreny pomocou noveho kluca
            if (recv_all(client_socket, client_validation, VALIDATION_SIZE) != VALIDATION_SIZE)
            {
                fprintf(stderr, ERR_KEY_VALIDATE_RECEIVE);
                transfer_complete = -1;
                break;
            }

            // Vytvorenie vlastneho validacneho kodu pouzitim rovnakeho algoritmu ako klient
            generate_key_validation(our_validation, session_key);
            // Porovnanie validacnych kodov - ak sa nezhoduju, kluce nie su synchronizovane
            if (memcmp(client_validation, our_validation, VALIDATION_SIZE) != 0)
            {
                fprintf(stderr, ERR_KEY_VALIDATE_MISMATCH);
                transfer_complete = -1;
                break;
            }

            // Bezpecne vymazanie stareho kluca z pamate
            secure_wipe(previous_session_key, KEY_SIZE);

            // Odoslanie potvrdenia klientovi, ze server je pripraveny pokracovat s novym klucom
            if (send_chunk_size_reliable(client_socket, KEY_ROTATION_READY) < 0)
            {
                fprintf(stderr, ERR_KEY_ROTATION_READY);
                transfer_complete = -1;
                break;
            }
            // Kratka pauza pre stabilizaciu komunikacie
            wait();
            continue;
        }

        // Spracovanie bloku dat a aktualizacia postupu
        // Prijatie zasifrovaneho bloku dat od klienta
        // - nonce: jednorazova hodnota pouzita pre tento blok
        // - tag: autentizacny tag na overenie integrity
        // - ciphertext: zasifrovane data
        if (receive_encrypted_chunk(client_socket, nonce, tag, ciphertext, chunk_size) < 0)
        {
            fprintf(stderr, ERR_RECEIVE_ENCRYPTED_CHUNK);
            break;
        }

        // Desifrovanie a autentizacia prijatych dat pomocou aktualneho kluca relacie
        if (crypto_aead_unlock(plaintext, tag, session_key, nonce, NULL, 0, ciphertext, chunk_size) != 0)
        {
            fprintf(stderr, ERR_DECRYPT_CHUNK_AUTH);
            break;
        }

        // Zapis desifrovanych dat do vystupneho suboru
        if (fwrite(plaintext, 1, chunk_size, file) != chunk_size)
        {
            fprintf(stderr, ERR_WRITE_TO_FILE);
            break;
        }

        // Aktualizacia pocitadiel pre sledovanie prenosu
        total_bytes += chunk_size;
        block_count++;

        // Aktualizacia postupu prenosu do konzoly
        if (total_bytes - last_progress_update >= PROGRESS_UPDATE_INTERVAL)
        {
            printf(LOG_PROGRESS_FORMAT, "Received", (float)total_bytes / PROGRESS_UPDATE_INTERVAL);
            fflush(stdout);
            last_progress_update = total_bytes;
        }
    }

    // Finalna sprava o stave prenosu s celkovym poctom prijatych dat
    if (transfer_complete == 1)
    {
        printf(LOG_SUCCESS_FORMAT, "received", (float)total_bytes / PROGRESS_UPDATE_INTERVAL);
    }
    else
    {
        fprintf(stderr, ERR_TRANSFER_INTERRUPTED);
    }

    // Ukoncenie a cistenie
    // - Zatvorenie vystupneho suboru
    // - Uvolnenie sietovych prostriedkov
    // - Navrat s kodom podla uspesnosti prenosu
    if (file != NULL)
    {
        fclose(file);
    }
    cleanup_sockets(client_socket, server_fd);
    cleanup_network();

    // Bezpecne vymazanie citlivych dat z pamate
    secure_wipe(key, KEY_SIZE);
    secure_wipe(session_key, KEY_SIZE);
    secure_wipe(buffer, TRANSFER_BUFFER_SIZE);
    secure_wipe(plaintext, TRANSFER_BUFFER_SIZE);
    secure_wipe(tag, TAG_SIZE);

    // Vymazanie key chain
    secure_wipe(&key_chain, sizeof(key_chain));

    return (transfer_complete == 1) ? 0 : -1;
}
