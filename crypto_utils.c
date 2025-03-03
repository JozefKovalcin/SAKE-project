/********************************************************************************
 * Program:    Kryptograficke nastroje pre zabezpeceny prenos
 * Subor:      crypto_utils.c
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      2025
 * 
 * Popis: 
 *     Implementacia kryptografickych operacii pre protokol SAKE: 
 *     - Implementacia SAKE protokolu pre autentificaciu a vymenu klucov
 *     - Bezpecne generovanie nahodnych cisel pre nonce a salt
 *     - Bezpecne odvodenie klucov pomocou Argon2
 *     - Rotacia klucov a ich validaciu pre pravidelne obmeny pocas prenosu
 *     - Odvodzovanie relacnych klucov zo zdielanych tajomstiev
 *     - Implementacia Doprednej ochrany pomocou jednosmernych funkcii
 * 
 * Zavislosti:
 *     - Monocypher 4.0.2 (sifrovacie algoritmy)
 *     - crypto_utils.h (deklaracie funkcii)
 *     - constants.h (konstanty programu)
 *******************************************************************************/

// Systemove kniznice
#include <stdio.h>        // Kniznica pre standardny vstup a vystup (nacitanie zo suborov, vypis na obrazovku)
#include <stdlib.h>       // Kniznica pre vseobecne funkcie (sprava pamate, konverzie, nahodne cisla)
#include <string.h>       // Kniznica pre pracu s retazcami (kopirovanie, porovnavanie, spajanie)

#ifdef _WIN32
#include <winsock2.h>     // Windows: Zakladna sietova kniznica
#include <windows.h>      // Windows: Zakladne systemove funkcie
#include <bcrypt.h>       // Windows: Kryptograficke funkcie
#else
#include <sys/stat.h>     // Linux: Operacie so subormi a ich atributmi
#include <sys/random.h>   // Linux: Generovanie kryptograficky bezpecnych nahodnych cisel
#include <errno.h>        // Linux: Kniznica pre systemove chyby
#include <string.h>       // Linux: Kniznica pre pracu s retazcami
#endif

#include "crypto_utils.h" // Pre kryptograficke funkcie
#include "constants.h"    // Add this include for constants

// Pomocna funkcia pre vypis kryptografickych dat
// Pouziva sa pri ladeni a kontrole
void print_hex(const char *label, uint8_t *data, int len) {
    // Kazdy bajt sa zobrazi ako dve hexadecimalne cislice
    printf("%s", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);  // %02x zobrazi cislo ako 2 hexadecimalne znaky s nulou na zaciatku
    }
    printf("\n");
}

// Generovanie kryptograficky bezpecnych nahodnych cisel
// Pouziva systemove generatory (BCrypt na Windows, getrandom na Linuxe)
void generate_random_bytes(uint8_t *buffer, size_t size) {
#ifdef __linux__
    if (getrandom(buffer, size, 0) == -1) {
        fprintf(stderr, ERR_RANDOM_LINUX, strerror(errno));
        exit(1);
    }
#elif defined(_WIN32)
    if (BCryptGenRandom(NULL, buffer, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        fprintf(stderr, ERR_RANDOM_WINDOWS);
        exit(1);
    }
#else
    #error "Unsupported platform for random number generation"
#endif
}

// Interna implementacia derivacie kluca
// Zdielana medzi klientom a serverom
// Parametre:
//   - password: heslo od uzivatela
//   - salt_input: existujuca sol (server) alebo NULL (klient)
//   - key: vystupny buffer pre kluc
//   - salt: vystupny buffer pre sol
//   - generate_salt: true pre klienta, false pre server
static int derive_key_internal(const char *password, const uint8_t *salt_input, 
                             uint8_t *key, uint8_t *salt, int generate_salt) {
    // Kontrola ci mame vsetky potrebne vstupy
    // Ak chyba heslo, kluc alebo sol, funkcia nemoze pokracovat
    if (!password || !key || !salt) {
        fprintf(stderr, ERR_KEY_DERIVE_PARAMS);
        return -1;
    }

    // Bud vytvorime novu sol (pre klienta) alebo pouzijeme existujucu (pre server)
    // Sol pre heslo - robi ho tazsie uhadnutelnym
    if (generate_salt) {
        generate_random_bytes(salt, SALT_SIZE);  // Generujeme novu nahodnu sol
    } else if (salt_input) {
        memcpy(salt, salt_input, SALT_SIZE);    // Pouzijeme existujucu sol
    } else {
        return -1;  // Nemame ziadnu sol, nemoze pokracovat
    }

    // Argon2 je funkcia na hashovanie hesiel, ktora:
    // - Potrebuje vela pamate (stazuje pouzitie specializovaneho hardveru na lamanie hesiel)
    // - Je pomala (chrani proti uhadnutiu hesla skusanim)
    // - Umoznuje paralelne spracovanie (moznost nastavit rychlost podla potreby)
    crypto_argon2_config config = {
        .algorithm = CRYPTO_ARGON2_I,           // Vyberie verziu algoritmu (I = Argon2i, D = Argon2d)
        .nb_blocks = ARGON2_MEMORY_BLOCKS,      // Kolko pamate sa pouzije (viac = bezpecnejsie)
        .nb_passes = ARGON2_ITERATIONS,         // Kolkokrat sa data prepocitaju (viac = bezpecnejsie)
        .nb_lanes = ARGON2_LANES               // Kolko jadier procesora sa moze vyuzit
    };
    
    crypto_argon2_inputs inputs = {
        .pass = (const uint8_t *)password,
        .pass_size = strlen(password),         // Dlzka hesla v bajtoch
        .salt = salt,
        .salt_size = SALT_SIZE                // Velkost soli (16 bajtov)
    };

    void *work_area = malloc(config.nb_blocks * 1024);    // Alokovanie pracovnej pamate (65536 * 1024 = 64 MB)
    if (!work_area) {
        fprintf(stderr, ERR_KEY_DERIVE_MEMORY);
        return -1;
    }

    crypto_argon2(key, KEY_SIZE, work_area, config, inputs, crypto_argon2_no_extras);
    
    // Po dokonceni vymazeme heslo z pamate
    // Zabranuje to jeho odcitaniu z pamate po ukonceni programu
    crypto_wipe((uint8_t *)password, strlen(password));    // Prepise pamat nulami
    
    free(work_area);

    print_hex(generate_salt ? "Vygenerovana sol: " : "Pouziva sa sol: ", salt, SALT_SIZE);
    print_hex("Odvodeny kluc: ", key, KEY_SIZE);

    return 0;
}

// Serverova implementacia derivacie kluca
// Pouziva prijatu sol od klienta
int derive_key_server(const char *password, const uint8_t *received_salt, 
                     uint8_t *key, uint8_t *salt) {
    return derive_key_internal(password, received_salt, key, salt, 0);
}

// Klientska implementacia derivacie kluca
// Generuje novu sol a odvodi kluc
int derive_key_client(const char *password, uint8_t *key, uint8_t *salt) {
    return derive_key_internal(password, NULL, key, salt, 1);
}

// Rotacia aktualneho kluca pre vytvorenie noveho
// Pouziva sa na pravidelnu obmenu klucov pre lepsiu bezpecnost
void rotate_key(uint8_t *current_key, const uint8_t *previous_key) {
    uint8_t nonce[NONCE_SIZE];
    // Pouzitie fixnej hodnoty nonce pre deterministicku rotaciu
    memset(nonce, 0xFF, NONCE_SIZE);
    
    // Pouzitie BLAKE2b s pevnymi parametrami pre deterministicke odvodzovanie klucov
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, KEY_SIZE);
    crypto_blake2b_update(&ctx, previous_key, KEY_SIZE);
    crypto_blake2b_update(&ctx, nonce, NONCE_SIZE);
    crypto_blake2b_final(&ctx, current_key);
    
    // Bezpecne vymazanie citlivych dat z pamate
    crypto_wipe(&ctx, sizeof(ctx));
    secure_wipe(nonce, NONCE_SIZE);
}

// Bezpecne vymazanie citlivych dat z pamate
// Volatile zabranuje optimalizatoru odstranit mazanie
void secure_wipe(void *data, size_t size) {
    volatile uint8_t *p = (volatile uint8_t *)data;
    while (size--) {
        *p++ = 0;
    }
}

// Vytvorenie validacneho kodu pre overenie spravnosti kluca
// Pouziva sa na kontrolu ci obe strany maju rovnaky kluc
void generate_key_validation(uint8_t *validation, const uint8_t *key) {
    crypto_blake2b_ctx ctx;
    // Inicializacia BLAKE2b hashovacej funkcie s vystupom velkosti VALIDATION_SIZE
    crypto_blake2b_init(&ctx, VALIDATION_SIZE);  // Vzdy pouzijeme 16 bajtov pre validaciu
    // Pridanie kluca do hashovacej funkcie
    crypto_blake2b_update(&ctx, key, KEY_SIZE);
    // Finalizacia a ziskanie vysledneho hashu do validation buffra
    crypto_blake2b_final(&ctx, validation);
    // Bezpecne vymazanie hashovacieho kontextu z pamate
    crypto_wipe(&ctx, sizeof(ctx));
}

// SAKE protokol - implementacia funkcii

// Odvodenie autentifikacneho kluca K' z hlavneho kluca K
// Autentifikacny kluc sa pouziva vyhradne na overenie identity stran
void derive_authentication_key(uint8_t *auth_key, const uint8_t *master_key) {
    crypto_blake2b_ctx ctx;
    // Inicializacia hashovacej funkcie pre vytvorenie noveho kluca
    crypto_blake2b_init(&ctx, KEY_SIZE);
    // Pridanie hlavneho kluca do hashu
    crypto_blake2b_update(&ctx, master_key, KEY_SIZE);
    // Pridanie specialneho tagu na odlisenie ucelov kluca
    crypto_blake2b_update(&ctx, (const uint8_t*)SAKE_DERIV_AUTH_TAG, strlen(SAKE_DERIV_AUTH_TAG));
    // Finalizacia a ziskanie autentifikacneho kluca
    crypto_blake2b_final(&ctx, auth_key);
    // Bezpecne vymazanie hashovacieho kontextu
    crypto_wipe(&ctx, sizeof(ctx));
    
    // Vypis odvodenych hodnot pre kontrolu
    print_hex("Derived authentication key: ", auth_key, KEY_SIZE);
}

// Generovanie vyzvy pre autentifikaciu
// Vytvara kryptograficku vyzvu, ktoru musi klient spravne odpovedat
void generate_challenge(uint8_t *challenge, uint8_t *server_nonce, 
                      const uint8_t *auth_key, const uint8_t *client_nonce) {
    // Vygenerovanie nahodneho nonce servera pre jedinecnost vyzvy
    generate_random_bytes(server_nonce, SAKE_NONCE_SERVER_SIZE);
    
    // Vytvorenie vyzvy pomocou BLAKE2b
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, SAKE_CHALLENGE_SIZE);
    // Kombinacia autentifikacneho kluca a nonce hodnot
    crypto_blake2b_update(&ctx, auth_key, KEY_SIZE);
    crypto_blake2b_update(&ctx, client_nonce, SAKE_NONCE_CLIENT_SIZE);
    crypto_blake2b_update(&ctx, server_nonce, SAKE_NONCE_SERVER_SIZE);
    // Finalizacia a ziskanie vyzvy
    crypto_blake2b_final(&ctx, challenge);
    // Bezpecne vymazanie kontextu
    crypto_wipe(&ctx, sizeof(ctx));
    
    // Vypis vygenerovanej vyzvy 
    print_hex("Generated challenge: ", challenge, SAKE_CHALLENGE_SIZE);
}

// Vypocet odpovede na vyzvu
// Pouziva sa na klientskej strane na vytvorenie odpovede na serverovu vyzvu
int compute_response(uint8_t *response, const uint8_t *auth_key,
                   const uint8_t *challenge, const uint8_t *server_nonce) {
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, SAKE_RESPONSE_SIZE);
    // Kombinacia autentifikacneho kluca, vyzvy a nonce servera
    crypto_blake2b_update(&ctx, auth_key, KEY_SIZE);
    crypto_blake2b_update(&ctx, challenge, SAKE_CHALLENGE_SIZE);
    crypto_blake2b_update(&ctx, server_nonce, SAKE_NONCE_SERVER_SIZE);
    // Finalizacia a ziskanie odpovede
    crypto_blake2b_final(&ctx, response);
    // Bezpecne vymazanie kontextu
    crypto_wipe(&ctx, sizeof(ctx));
    
    // Vypis vypocitanej odpovede 
    print_hex("Computed response: ", response, SAKE_RESPONSE_SIZE);
    return 0;
}

// Overenie odpovede na vyzvu
// Pouziva sa na strane servera na overenie, ci klient ma spravny kluc
int verify_response(const uint8_t *response, const uint8_t *auth_key,
                  const uint8_t *challenge, const uint8_t *server_nonce) {
    // Vytvorenie ocakavanej odpovede lokalnym vypoctom
    uint8_t expected_response[SAKE_RESPONSE_SIZE];
    
    // Vypocitanie odpovede rovnakym algoritmom ako klient
    compute_response(expected_response, auth_key, challenge, server_nonce);
    
    // Porovnanie ocakavanej a prijatej odpovede v konstatnom case
    // crypto_verify32 zabranuje casovym utokom porovnavanim v konstatnom case
    if (crypto_verify32(expected_response, response) != 0) {
        fprintf(stderr, MSG_SAKE_AUTH_FAILED);
        return -1;
    }
    
    // Autentifikacia uspesna
    printf(MSG_SAKE_AUTH_SUCCESS);
    return 0;
}

// Odvodenie kluca relacie z hlavneho kluca a nonce
// Vytvara unikatny kluc pre kazdu relaciu
void derive_session_key(uint8_t *session_key, const uint8_t *master_key,
                       const uint8_t *client_nonce, const uint8_t *server_nonce) {
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, SESSION_KEY_SIZE);
    // Kombinacia hlavneho kluca, nonce hodnot a specialneho tagu
    crypto_blake2b_update(&ctx, master_key, KEY_SIZE);
    crypto_blake2b_update(&ctx, client_nonce, SAKE_NONCE_CLIENT_SIZE);
    crypto_blake2b_update(&ctx, server_nonce, SAKE_NONCE_SERVER_SIZE);
    // Pridanie specialneho tagu pre odlisenie ucelov kluca
    crypto_blake2b_update(&ctx, (const uint8_t*)SAKE_DERIV_SESSION_TAG, strlen(SAKE_DERIV_SESSION_TAG));
    // Finalizacia a ziskanie kluca relacie
    crypto_blake2b_final(&ctx, session_key);
    // Bezpecne vymazanie kontextu
    crypto_wipe(&ctx, sizeof(ctx));
    
    // Vypis odvodeneho kluca relacie 
    print_hex("Derived session key: ", session_key, SESSION_KEY_SIZE);
}

// Evolucia klucov po vytvoreni relacie
// Zabezpecuje doprednu ochranu - aj pri kompromitacii aktualneho kluca
// nie je mozne odhalit predchadzajuce spravy
void evolve_keys(uint8_t *master_key, uint8_t *auth_key, uint64_t counter) {
    // Ulozenie povodnych klucov pre neskor
    uint8_t old_master[KEY_SIZE];
    memcpy(old_master, master_key, KEY_SIZE);
    
    // Evolucia hlavneho kluca K pomocu hashovania s citacom
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, KEY_SIZE);
    crypto_blake2b_update(&ctx, master_key, KEY_SIZE);
    // Pridanie hodnoty citaca pre jedinecnost
    crypto_blake2b_update(&ctx, (uint8_t*)&counter, SAKE_KEY_COUNTER_SIZE);
    // Pridanie specialneho tagu pre tento ucel
    crypto_blake2b_update(&ctx, (const uint8_t*)SAKE_DERIV_KEY_TAG, strlen(SAKE_DERIV_KEY_TAG));
    // Finalizacia a ziskanie noveho hlavneho kluca
    crypto_blake2b_final(&ctx, master_key);
    
    // Odvodenie noveho autentifikacneho kluca K' z noveho hlavneho kluca
    derive_authentication_key(auth_key, master_key);
    
    // Bezpecne vymazanie starych hodnot z pamate
    secure_wipe(old_master, KEY_SIZE);
    crypto_wipe(&ctx, sizeof(ctx));
}