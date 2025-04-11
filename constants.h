/********************************************************************************
 * Program:    Konstanty pre zabezpeceny prenos suborov
 * Subor:      constants.h
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      05-03-2025
 *
 * Popis:
 *     Hlavickovy subor obsahujuci vsetky konstanty pouzivane v programe:
 *     - Konstanty SAKE protokolu pre autentizaciu a vymenu klucov
 *     - Sietove nastavenia a casove limity
 *     - Velkosti vyrovnavacich pamatí
 *     - Kryptograficke parametre pre ChaCha20-Poly1305
 *     - Konfiguraciu Argon2 pre odvodenie klucov
 *     - Riadiace konstanty pre protokol
 *
 * Zavislosti:
 *     - errors.h
 *******************************************************************************/

#ifndef CONSTANTS_H
#define CONSTANTS_H

#include "errors.h"

// Sietove nastavenia
// #define PORT 8080                          // Cislo portu pre komunikaciu medzi klientom a serverom
#define MAX_PENDING_CONNECTIONS 3 // Maximalny pocet cakajucich spojeni v rade

// Casove nastavenia
#define SOCKET_SHUTDOWN_DELAY_MS 1000 // Cas cakania pred ukoncenim socketu v milisekundach
#define WAIT_DELAY_MS 250             // Cas cakania medzi pokusmi o synchronizaciu
#define SOCKET_TIMEOUT_MS 10000       // Maximalny cas cakania na sietovu operaciu
#define WAIT_FILE_NAME 30000          // Cas cakania na prijatie nazvu suboru
#define KEY_EXCHANGE_TIMEOUT_MS 5000  // Cas cakania na vymenu klucov

// Nastavenia opakovanych pokusov
#define MAX_RETRIES 3       // Kolko krat sa ma operacia opakovat pri zlyhaniach
#define RETRY_DELAY_MS 1000 // Cas cakania medzi opakovaniami v milisekundach
#define ACK_SIZE 4          // Velkost potvrdzujucej spravy v bajtoch

// Kryptograficke parametre
#define KEY_SIZE 32              // Velkost sifrovacieho kluca v bajtoch (256 bitov)
#define NONCE_SIZE 24            // Velkost jednorazovej hodnoty v bajtoch (192 bitov)
#define TAG_SIZE 16              // Velkost autentizacneho kodu v bajtoch (128 bitov)
#define SALT_SIZE 16             // Velkost soli pre derivaciu kluca (128 bitov)
#define VALIDATION_SIZE 16       // Velkost overovacich dat v bajtoch
#define SESSION_KEY_SIZE 32      // Velkost kluca pre jedno spojenie
#define WORK_AREA_SIZE (1 << 16) // Velkost pracovnej pamate pre Argon2

// Parametre rotacie klucov
#define KEY_ROTATION_BLOCKS 1024         // Po kolkych blokoch sa ma kluc zmenit
#define KEY_ROTATION_MARKER 0xFFFFFFFF   // Specialna hodnota oznacujuca rotaciu kluca
#define KEY_ROTATION_ACK 0xFFFFFFFE      // Potvrdenie prijatia noveho kluca
#define KEY_ROTATION_READY 0xFFFFFFFD    // Signal pripravenosti na novy kluc
#define KEY_ROTATION_VALIDATE 0xFFFFFFFB // Kontrola spravnosti noveho kluca

// Priznaky nastavenia spojenia
#define SESSION_SETUP_START 0xFFFFFFF0 // Zaciatok vytvarania spojenia
#define SESSION_SETUP_DONE 0xFFFFFFF3  // Uspesne vytvorene spojenie

// Specialne hodnoty pre protokol
#define MAGIC_READY "READY" // Kontrolne retazce pre overenie spravnosti komunikacie
#define MAGIC_KEYOK "KEYOK"
#define MAGIC_TACK "TACK"
#define SESSION_SYNC_MAGIC "SKEY" // Hodnoty pre synchronizaciu spojenia
#define SESSION_SYNC_SIZE 4

// Velkosti vyrovnavacich pamatí
#define PASSWORD_BUFFER_SIZE 128               // Maximalna dlzka hesla
#define FILE_NAME_BUFFER_SIZE 240              // Maximalna dlzka nazvu suboru
#define NEW_FILE_NAME_BUFFER_SIZE 256          // Maximalna dlzka noveho nazvu suboru
#define TRANSFER_BUFFER_SIZE 4096              // Velkost bloku pre prenos dat
#define SIGNAL_SIZE 5                          // Velkost kontrolnych sprav
#define PROGRESS_UPDATE_INTERVAL (1024 * 1024) // Interval aktualizacie priebehu

// Konfiguracia Argon2 (funkcia pre odvodzovanie klucov)
#define ARGON2_MEMORY_BLOCKS 65536 // Kolko pamate pouzit (v 1KB blokoch)
#define ARGON2_ITERATIONS 3        // Kolko krat sa ma heslo prehashovat
#define ARGON2_LANES 1             // Kolko paralelnych vypoctov povolit

// Operacie so subormi
#define FILE_PREFIX "received_" // Predpona pre nazvy prijatych suborov
#define FILE_MODE_READ "rb"     // Mod otvarania suboru pre citanie (binarny)
#define FILE_MODE_WRITE "wb"    // Mod otvarania suboru pre zapis (binarny)

// Nastavenia klienta
#define DEFAULT_SERVER_ADDRESS "127.0.0.1"                         // Predvolena IP adresa servera (localhost)
#define IP_ADDRESS_PROMPT "Enter server IP address (default %s): " // Vyzva na zadanie IP adresy servera
#define PORT_PROMPT "Enter port number (1-65535): "                // Vyzva na zadanie cisla portu

// Texty pouzivatelskeho rozhrania
#define PASSWORD_PROMPT "Enter password: "                       // Vyzva na zadanie hesla pre klienta
#define PASSWORD_PROMPT_SERVER "Enter password for decryption: " // Vyzva na zadanie hesla pre server

// Systemove spravy
#define LOG_SERVER_START "Server is running on port %d. Waiting for client connection...\n" // Sprava o spusteni servera
#define LOG_TRANSFER_START "Starting file transfer...\n"                                    // Sprava o zacati prenosu
#define LOG_TRANSFER_COMPLETE "Transfer complete!\n"                                        // Sprava o dokonceni prenosu
#define LOG_SESSION_START "Starting session setup...\n"                                     // Sprava o zacati vytvarania spojenia
#define LOG_SESSION_COMPLETE "Secure session established successfully\n"                    // Sprava o uspesnom vytvoreni spojenia
#define LOG_PROGRESS_FORMAT "\rProgress: %s %.2f MB..."                                     // Format spravy o priebehu prenosu
#define LOG_SUCCESS_FORMAT "Success: File transfer completed. Total bytes %s: %.3f MB\n"    // Format spravy o uspesnom dokonceni

// Spravy o stave spojenia
#define MSG_CONNECTION_ACCEPTED "Connection accepted from %s:%d\n"                                           // Informacia o prijatom spojeni
#define MSG_KEY_ACK_RECEIVED "Received key acknowledgment from server\n"                                     // Potvrdenie prijatia kluca
#define MSG_ACK_SENDING "Sending acknowledgment (attempt %d/%d)...\n"                                        // Odosielanie potvrdenia
#define MSG_ACK_RETRY "Failed to send acknowledgment, retrying in %d ms...\n"                                // Opakovanie odoslania potvrdenia
#define MSG_ACK_WAITING "Waiting for acknowledgment (attempt %d/%d)...\n"                                    // Cakanie na potvrdenie
#define MSG_ACK_RETRY_RECEIVE "Failed to receive acknowledgment (received %d bytes), retrying in %d ms...\n" // Opakovanie prijatia potvrdenia

// Spravy pre odosielanie suborov
#define MSG_FILE_LIST "Files in the project directory:\n"                  // Zobrazenie zoznamu suborov
#define MSG_ENTER_FILENAME "Enter filename to send (max 239 characters): " // Vyzva na zadanie nazvu suboru
#define MSG_ACK_RECEIVED "Received acknowledgment from server.\n"          // Potvrdenie prijatia spravy
#define MSG_KEY_ROTATION "Initiating key rotation at block %llu\n"         // Informacia o zmene kluca
#define MSG_RETRY_FAILED "Send failed, retrying... (%d attempts left)\n"   // Nepodarilo sa odoslat, opakovanie
#define MSG_CHUNK_FAILED "Error: Failed to send chunk after all retries\n" // Chyba pri odosielani bloku po vsetkych opakovaniach
#define MSG_EOF_FAILED "Error: Failed to send EOF marker\n"                // Chyba pri odosielani EOF markera

// Protokolove konstanty
#define MAGIC_READY "READY" // Signal pripravenosti
#define MAGIC_KEYOK "KEYOK" // Signal potvrdenia kluca
#define MAGIC_TACK "TACK"   // Signal potvrdenia prenosu

// SAKE Protokolove konstanty
#define SAKE_CHALLENGE_SIZE 32                // Velkost vyzvy v bajtoch
#define SAKE_RESPONSE_SIZE 32                 // Velkost odpovede v bajtoch
#define SAKE_DERIV_KEY_TAG "SAKE_K"           // Tag pre odvodzovanie hlavneho kluca K
#define SAKE_DERIV_AUTH_TAG "SAKE_K_AUTH"     // Tag pre odvodzovanie autentizacneho kluca K'
#define SAKE_DERIV_SESSION_TAG "SAKE_SESSION" // Tag pre odvodzovanie kluca relacie
#define SAKE_KEY_COUNTER_SIZE 8               // Velkost citaca verzie kluca
#define SAKE_NONCE_CLIENT_SIZE 16             // Velkost nonce klienta
#define SAKE_NONCE_SERVER_SIZE 16             // Velkost nonce servera

// Hodnoty pre vysledok auntentizacie
#define AUTH_SUCCESS 0x01 // Kod pre uspesnu autentizaciu
#define AUTH_FAILED 0x00  // Kod pre neuspesnu autentizaciu

// SAKE Protokolove spravy
#define MSG_SAKE_AUTH_SUCCESS "SAKE response verified successfully\n" // Uspesna autentizacia
#define MSG_SAKE_AUTH_FAILED "SAKE response verification failed\n"    // Neuspesna autentizacia

#endif // CONSTANTS_H
