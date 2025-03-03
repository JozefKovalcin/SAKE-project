/********************************************************************************
 * Program:    Konstanty pre zabezpeceny prenos suborov
 * Subor:      constants.h
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      2025
 *
 * Popis: 
 *     Hlavickovy subor obsahujuci vsetky konstanty pouzivane v programe:
 *     - Konstanty SAKE protokolu pre autentifikaciu a vymenu klucov
 *     - Sietove nastavenia a casove limity
 *     - Velkosti vyrovnavacich pamatí
 *     - Kryptograficke parametre pre ChaCha20-Poly1305
 *     - Konfiguraciu Argon2 pre odvodenie klucov
 *     - Chybove a informacne spravy
 *     - Riadiace konstanty pre protokol
 *
 * Zavislosti:
 *     - Ziadne externe zavislosti
 *******************************************************************************/

#ifndef CONSTANTS_H
#define CONSTANTS_H

// Sietove nastavenia
#define PORT 8080                          // Cislo portu pre komunikaciu medzi klientom a serverom
#define MAX_PENDING_CONNECTIONS 3          // Maximalny pocet cakajucich spojeni v rade

// Casove nastavenia
#define SOCKET_SHUTDOWN_DELAY_MS 1000      // Cas cakania pred ukoncenim socketu v milisekundach
#define WAIT_DELAY_MS 250                  // Cas cakania medzi pokusmi o synchronizaciu
#define SOCKET_TIMEOUT_MS 10000            // Maximalny cas cakania na sietovu operaciu
#define WAIT_FILE_NAME 30000               // Cas cakania na prijatie nazvu suboru
#define KEY_EXCHANGE_TIMEOUT_MS 5000       // Cas cakania na vymenu klucov

// Nastavenia opakovanych pokusov
#define MAX_RETRIES 3                      // Kolko krat sa ma operacia opakovat pri zlyhaniach
#define RETRY_DELAY_MS 1000                // Cas cakania medzi opakovaniami v milisekundach
#define ACK_SIZE 4                         // Velkost potvrdzujucej spravy v bajtoch

// Kryptograficke parametre
#define KEY_SIZE 32                        // Velkost sifrovacieho kluca v bajtoch (256 bitov)
#define NONCE_SIZE 24                      // Velkost jednorazovej hodnoty v bajtoch (192 bitov)
#define TAG_SIZE 16                        // Velkost autentifikacneho kodu v bajtoch (128 bitov)
#define SALT_SIZE 16                       // Velkost soli pre derivaciu kluca (128 bitov)
#define VALIDATION_SIZE 16                 // Velkost overovacich dat v bajtoch
#define SESSION_KEY_SIZE 32                // Velkost kluca pre jedno spojenie
#define WORK_AREA_SIZE (1 << 16)           // Velkost pracovnej pamate pre Argon2

// Parametre rotacie klucov
#define KEY_ROTATION_BLOCKS 1024           // Po kolkych blokoch sa ma kluc zmenit
#define KEY_ROTATION_MARKER 0xFFFFFFFF     // Specialna hodnota oznacujuca rotaciu kluca
#define KEY_ROTATION_ACK 0xFFFFFFFE        // Potvrdenie prijatia noveho kluca
#define KEY_ROTATION_READY 0xFFFFFFFD      // Signal pripravenosti na novy kluc
#define KEY_ROTATION_VALIDATE 0xFFFFFFFB   // Kontrola spravnosti noveho kluca

// Priznaky nastavenia spojenia
#define SESSION_SETUP_START 0xFFFFFFF0     // Zaciatok vytvarania spojenia
#define SESSION_SETUP_DONE 0xFFFFFFF3      // Uspesne vytvorene spojenie

// Specialne hodnoty pre protokol
#define MAGIC_READY "READY"               // Kontrolne retazce pre overenie spravnosti komunikacie
#define MAGIC_KEYOK "KEYOK"               
#define MAGIC_TACK "TACK"                 
#define SESSION_SYNC_MAGIC "SKEY"        // Hodnoty pre synchronizaciu spojenia
#define SESSION_SYNC_SIZE 4

// Velkosti vyrovnavacich pamatí
#define PASSWORD_BUFFER_SIZE 128           // Maximalna dlzka hesla
#define FILE_NAME_BUFFER_SIZE 240          // Maximalna dlzka nazvu suboru
#define NEW_FILE_NAME_BUFFER_SIZE 256      // Maximalna dlzka noveho nazvu suboru
#define TRANSFER_BUFFER_SIZE 4096          // Velkost bloku pre prenos dat
#define SIGNAL_SIZE 5                      // Velkost kontrolnych sprav
#define PROGRESS_UPDATE_INTERVAL (1024 * 1024) // Interval aktualizacie priebehu

// Konfiguracia Argon2 (funkcia pre odvodzovanie klucov)
#define ARGON2_MEMORY_BLOCKS 65536         // Kolko pamate pouzit (v 1KB blokoch)
#define ARGON2_ITERATIONS 3                // Kolko krat sa ma heslo prehashovat
#define ARGON2_LANES 1                     // Kolko paralelnych vypoctov povolit

// Operacie so subormi
#define FILE_PREFIX "received_"           // Predpona pre nazvy prijatych suborov
#define FILE_MODE_READ "rb"               // Mod otvarania suboru pre citanie (binarny)
#define FILE_MODE_WRITE "wb"              // Mod otvarania suboru pre zapis (binarny)

// Nastavenia klienta
#define DEFAULT_SERVER_ADDRESS "127.0.0.1" // Predvolena IP adresa servera (localhost)

// Texty pouzivatelskeho rozhrania
#define PASSWORD_PROMPT "Enter password: " // Vyzva na zadanie hesla pre klienta
#define PASSWORD_PROMPT_SERVER "Enter password for decryption: " // Vyzva na zadanie hesla pre server

// Systemove spravy
#define LOG_SERVER_START "Server is running. Waiting for client connection...\n" // Sprava o spusteni servera
#define LOG_TRANSFER_START "Starting file transfer...\n" // Sprava o zacati prenosu
#define LOG_TRANSFER_COMPLETE "Transfer complete!\n" // Sprava o dokonceni prenosu
#define LOG_SESSION_START "Starting session setup...\n" // Sprava o zacati vytvarania spojenia
#define LOG_SESSION_COMPLETE "Secure session established successfully\n" // Sprava o uspesnom vytvoreni spojenia
#define LOG_PROGRESS_FORMAT "\rProgress: %s %.2f MB..." // Format spravy o priebehu prenosu
#define LOG_SUCCESS_FORMAT "Success: File transfer completed. Total bytes %s: %.3f MB\n" // Format spravy o uspesnom dokonceni

// Zakladne chybove spravy
#define ERR_SOCKET_SETUP "Error: Failed to set up server socket (%s)\n" // Chyba pri nastaveni socketu servera 
#define ERR_CLIENT_ACCEPT "Error: Failed to accept client connection (%s)\n" // Chyba pri prijimani klientskeho spojenia
#define ERR_HANDSHAKE "Error: Failed during initial handshake - check network connection\n" // Chyba pri pociatocnej synchronizacii
#define ERR_SALT_RECEIVE "Error: Failed to receive salt from client\n" // Chyba pri prijimani kryptografickej soli
#define ERR_KEY_DERIVATION "Error: Key derivation failed\n" // Chyba pri odvodzovani kluca
#define ERR_KEY_ACK "Error: Failed to send key acknowledgment\n" // Chyba pri potvrdzovani kluca
#define ERR_SESSION_SETUP "Error: Failed to start session setup\n" // Chyba pri vytvarani spojenia
#define ERR_KEY_EXCHANGE "Error: Key exchange failed\n" // Chyba pri vymene klucov
#define ERR_SESSION_NONCE "Error: Failed to receive session nonce\n" // Chyba pri prijimani nonce pre spojenie
#define ERR_SESSION_CONFIRM "Error: Failed to confirm session setup\n" // Chyba pri potvrdzovani spojenia
#define ERR_FILENAME_RECEIVE "Error: Failed to receive file name from client (%s)\n" // Chyba pri prijimani nazvu suboru
#define ERR_FILE_CREATE "Error: Failed to create file '%s' (%s)\n" // Chyba pri vytvarani suboru
#define ERR_CHUNK_SIZE "Error: Failed to read chunk size\n" // Chyba pri citani velkosti bloku dat
#define ERR_CHUNK_PROCESS "Error: Failed to process chunk\n" // Chyba pri spracovani bloku dat
#define ERR_TRANSFER_INTERRUPTED "Error: File transfer failed or was interrupted prematurely\n" // Chyba pri preruseni prenosu

// Chybove spravy pre sietove operacie
#define ERR_WINSOCK_INIT "Error: Winsock initialization failed\n" // Chyba pri inicializacii Winsock
#define ERR_SOCKET_CREATE "Error: Socket creation error\n" // Chyba pri vytvarani socketu
#define ERR_SOCKET_BIND "Error: Bind failed (%s)\n" // Chyba pri bind operacii
#define ERR_SOCKET_LISTEN "Error: Listen failed (%s)\n" // Chyba pri listen operacii
#define ERR_SOCKET_ACCEPT "Error: Accept failed\n" // Chyba pri prijimani spojenia
#define ERR_INVALID_ADDRESS "Error: Invalid address\n" // Neplatna adresa
#define ERR_CONNECTION_FAILED "Error: Connection failed\n" // Chyba pri pripojeni
#define ERR_READY_SIGNAL "Error: Failed to send ready signal\n" // Chyba pri odosielani signalu pripravenosti
#define ERR_READY_RECEIVE "Error: Failed to receive ready signal\n" // Chyba pri prijimani signalu pripravenosti
#define ERR_KEY_ACK_SEND "Error: Failed to send key acknowledgment (sent %d bytes)\n" // Chyba pri odosielani potvrdenia kluca
#define ERR_KEY_ACK_RECEIVE "Error: Failed to receive key acknowledgment (received %d bytes)\n" // Chyba pri prijimani potvrdenia kluca
#define ERR_KEY_ACK_INVALID "Error: Invalid key acknowledgment received ('%.*s')\n" // Neplatne potvrdenie kluca
#define ERR_SYNC_SEND "Failed to send sync message\n" // Chyba pri odosielani synchronizacnej spravy
#define ERR_SYNC_INVALID "Invalid sync acknowledgment\n" // Neplatne potvrdenie synchronizacie
#define ERR_SYNC_MESSAGE "Invalid sync message\n" // Neplatna synchronizacna sprava
#define ERR_SYNC_ACK_SEND "Failed to send sync acknowledgment\n" // Chyba pri odosielani potvrdenia synchronizacie

// Chybove spravy pre rotaciu klucov
#define ERR_KEY_VALIDATE_SIGNAL "Error: Failed to receive validation marker\n" // Chyba pri prijimani validacneho markera
#define ERR_KEY_VALIDATE_RECEIVE "Error: Failed to receive key validation\n" // Chyba pri prijimani validacie kluca
#define ERR_KEY_VALIDATE_MISMATCH "Error: Key validation failed - keys do not match\n" // Kluce sa nezhoduju pri validacii
#define ERR_KEY_ROTATION_READY "Error: Failed to confirm key rotation\n" // Chyba pri potvrdeni pripravenosti na novy kluc

// Chybove spravy pre casove limity
#define ERR_TIMEOUT_RECV "Error: Failed to set receive timeout (%s)\n" // Chyba pri nastaveni timeoutu pre prijem
#define ERR_TIMEOUT_SEND "Error: Failed to set send timeout (%s)\n" // Chyba pri nastaveni timeoutu pre odosielanie
#define ERR_KEEPALIVE "Warning: Failed to set keepalive\n" // Chyba pri nastaveni keepalive spojenia

// Chybove spravy pre kryptograficke operacie
#define ERR_RANDOM_LINUX "Error: Failed to generate random bytes (%s)\n" // Chyba pri generovani nahodnych cisel na Linuxe
#define ERR_RANDOM_WINDOWS "Error: Failed to generate random bytes (BCrypt error)\n" // Chyba pri generovani nahodnych cisel na Windows
#define ERR_KEY_DERIVE_PARAMS "Error: Invalid parameters for key derivation\n" // Neplatne parametre pre derivaciu kluca
#define ERR_KEY_DERIVE_MEMORY "Error: Failed to allocate memory for key derivation\n" // Nedostatok pamate pre derivaciu kluca

// Spravy o stave spojenia
#define MSG_CONNECTION_ACCEPTED "Connection accepted from %s:%d\n" // Informacia o prijatom spojeni
#define MSG_KEY_ACK_RECEIVED "Received key acknowledgment from server\n" // Potvrdenie prijatia kluca
#define MSG_ACK_SENDING "Sending acknowledgment (attempt %d/%d)...\n" // Odosielanie potvrdenia
#define MSG_ACK_RETRY "Failed to send acknowledgment, retrying in %d ms...\n" // Opakovanie odoslania potvrdenia
#define MSG_ACK_WAITING "Waiting for acknowledgment (attempt %d/%d)...\n" // Cakanie na potvrdenie
#define MSG_ACK_RETRY_RECEIVE "Failed to receive acknowledgment (received %d bytes), retrying in %d ms...\n" // Opakovanie prijatia potvrdenia

// Chybove sprave pre odosielanie suborov
#define MSG_FILE_LIST "Files in the project directory:\n" // Zobrazenie zoznamu suborov
#define MSG_ENTER_FILENAME "Enter filename to send (max 239 characters): " // Vyzva na zadanie nazvu suboru
#define MSG_ACK_RECEIVED "Received acknowledgment from server.\n" // Potvrdenie prijatia spravy
#define MSG_KEY_ROTATION "Initiating key rotation at block %llu\n" // Informacia o zmene kluca
#define MSG_RETRY_FAILED "Send failed, retrying... (%d attempts left)\n" // Nepodarilo sa odoslat, opakovanie
#define MSG_CHUNK_FAILED "Error: Failed to send chunk after all retries\n" // Chyba pri odosielani bloku po vsetkych opakovaniach
#define MSG_EOF_FAILED "Error: Failed to send EOF marker\n" // Chyba pri odosielani EOF markera
#define ERR_FILENAME_LENGTH "Error: File name exceeds maximum length of 239 characters\n" // Chyba pri prekroceni max dlzky nazvu suboru
#define ERR_FILENAME_READ "Error: Failed to read file name from input\n" // Chyba pri citani nazvu suboru
#define ERR_FILE_OPEN "Error: Cannot open file '%s' (%s)\n" // Chyba pri otvarani suboru
#define ERR_FILENAME_SEND "Error: Failed to send file name to server (%s)\n" // Chyba pri odosielani nazvu suboru
#define ERR_KEY_ROTATION_ACK "Error: Failed to acknowledge key rotation\n" // Chyba pri potvrdeni rotacie kluca

// Protokolove konstanty
#define MAGIC_READY "READY" // Signal pripravenosti   
#define MAGIC_KEYOK "KEYOK" // Signal potvrdenia kluca 
#define MAGIC_TACK  "TACK"  // Signal potvrdenia prenosu    

// SAKE Protokolove konstanty
#define SAKE_CHALLENGE_SIZE 32       // Velkost vyzvy v bajtoch
#define SAKE_RESPONSE_SIZE 32        // Velkost odpovede v bajtoch
#define SAKE_DERIV_KEY_TAG "SAKE_K"  // Tag pre odvodzovanie hlavneho kluca K
#define SAKE_DERIV_AUTH_TAG "SAKE_K_AUTH" // Tag pre odvodzovanie autentifikacneho kluca K'
#define SAKE_DERIV_SESSION_TAG "SAKE_SESSION" // Tag pre odvodzovanie kluca relacie
#define SAKE_KEY_COUNTER_SIZE 8      // Velkost citaca verzie kluca
#define SAKE_NONCE_CLIENT_SIZE 16    // Velkost nonce klienta
#define SAKE_NONCE_SERVER_SIZE 16    // Velkost nonce servera

// SAKE Protokolove spravy
#define MSG_SAKE_AUTH_SUCCESS "SAKE response verified successfully\n" // Uspesna autentifikacia
#define MSG_SAKE_AUTH_FAILED "SAKE response verification failed\n"   // Neuspesna autentifikacia

// SAKE chybove spravy
#define ERR_CLIENT_NONCE_SEND "Error: Failed to send client nonce\n" // Chyba pri odosielani nonce klienta
#define ERR_SERVER_CHALLENGE "Error: Failed to receive server challenge\n" // Chyba pri prijimani vyzvy od servera
#define ERR_COMPUTE_RESPONSE "Error: Failed to compute SAKE response\n" // Chyba pri vypocte odpovede
#define ERR_SEND_RESPONSE "Error: Failed to send response\n" // Chyba pri odosielani odpovede
#define ERR_RECEIVE_CLIENT_NONCE "Error: Failed to receive client nonce\n" // Chyba pri prijimani nonce klienta
#define ERR_SEND_CHALLENGE "Error: Failed to send challenge\n" // Chyba pri odosielani vyzvy
#define ERR_RECEIVE_RESPONSE "Error: Failed to receive response\n" // Chyba pri prijimani odpovede
#define ERR_CLIENT_AUTH_FAILED "Error: Client authentication failed\n" // Chyba pri autentifikacii klienta

// Chybove spravy pre spracovanie blokov
#define ERR_RECEIVE_ENCRYPTED_CHUNK "Error: Failed to receive encrypted chunk\n" // Chyba pri prijimani zasifrovaneho bloku
#define ERR_DECRYPT_CHUNK_AUTH "Error: Failed to decrypt chunk (authentication failed)\n" // Chyba pri desifrovani bloku
#define ERR_WRITE_TO_FILE "Error: Failed to write to file\n" // Chyba pri zapisovani do suboru

#endif // CONSTANTS_H
