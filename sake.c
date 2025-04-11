/*******************************************************************************
 * Program:    SAKE (Symmetric Authenticated Key Exchange) Protocol
 * Subor:      sake.c
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      05-03-2025
 *
 * Popis:
 *     Implementacia funkcii SAKE protokolu pre autentizaciu a vymenu klucov:
 *     - Odvodzovanie autentizacnych klucov
 *     - Generovanie a overovanie vyziev
 *     - Vytvaranie relacnych klucov
 *     - Evolucia klucov pre forward secrecy
 *
 * Zavislosti:
 *     - Monocypher 4.0.2 (sifrovacie algoritmy)
 *     - sake.h (deklaracie funkcii)
 *     - constants.h (konstanty programu)
 *     - crypto_utils.h (pomocne kryptograficke funkcie)
 ******************************************************************************/

#include <stdio.h>  // Kniznica pre standardny vstup a vystup
#include <stdlib.h> // Kniznica pre vseobecne funkcie
#include <string.h> // Kniznica pre pracu s retazcami

#include "sake.h"         // Pre deklaracie SAKE funkcii
#include "crypto_utils.h" // Pre pomocne kryptograficke funkcie
#include "constants.h"    // Pre konstanty programu

// Odvodenie autentizacneho kluca K' z hlavneho kluca K
// Pouziva BLAKE2b hash funkciu pre bezpecne odvodenie autentizacneho kluca
void derive_authentication_key(uint8_t *auth_key, const uint8_t *master_key)
{
    crypto_blake2b_ctx ctx;                                                                         // Inicializacia kontextu pre BLAKE2b
    crypto_blake2b_init(&ctx, KEY_SIZE);                                                            // Nastavenie dlzky vystupu na velkost kluca
    crypto_blake2b_update(&ctx, master_key, KEY_SIZE);                                              // Pridanie hlavneho klucu do hashu
    crypto_blake2b_update(&ctx, (const uint8_t *)SAKE_DERIV_AUTH_TAG, strlen(SAKE_DERIV_AUTH_TAG)); // Pridamanie tagu pre separaciu domen
    crypto_blake2b_final(&ctx, auth_key);                                                           // Finalizacia a ziskanie vysledneho autentizacneho kluca
    crypto_wipe(&ctx, sizeof(ctx));                                                                 // Bezpecne vymazanie citliveho kontextu z pamate

    print_hex("Derived authentication key: ", auth_key, KEY_SIZE);
}

// Generovanie vyzvy pre autentizaciu
// Vytvara challenge hodnotu pre overenie identity komunikujucej strany
void generate_challenge(uint8_t *challenge, uint8_t *server_nonce,
                        const uint8_t *auth_key, const uint8_t *client_nonce)
{
    // Vygenerovanie nahodneho nonce servera pre jedinecnost kazdeho spojenia
    generate_random_bytes(server_nonce, SAKE_NONCE_SERVER_SIZE);

    // Vytvorenie vyzvy pomocou BLAKE2b kombinaciou kluca a nonce hodnot
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, SAKE_CHALLENGE_SIZE);
    crypto_blake2b_update(&ctx, auth_key, KEY_SIZE);                   // Pridanie tajneho kluca
    crypto_blake2b_update(&ctx, client_nonce, SAKE_NONCE_CLIENT_SIZE); // Pridanie klientskej nonce
    crypto_blake2b_update(&ctx, server_nonce, SAKE_NONCE_SERVER_SIZE); // Pridanie serverovej nonce
    crypto_blake2b_final(&ctx, challenge);                             // Finalizacia a ziskanie vyzvy
    crypto_wipe(&ctx, sizeof(ctx));                                    // Bezpecne vymazanie citliveho kontextu

    print_hex("Generated challenge: ", challenge, SAKE_CHALLENGE_SIZE);
}

// Vypocet odpovede na vyzvu
// Klient pocita svoju odpoved na zaklade prijatej vyzvy
int compute_response(uint8_t *response, const uint8_t *auth_key,
                     const uint8_t *challenge, const uint8_t *server_nonce)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, SAKE_RESPONSE_SIZE);
    crypto_blake2b_update(&ctx, auth_key, KEY_SIZE);                   // Tajny kluc, ktory maju obe strany
    crypto_blake2b_update(&ctx, challenge, SAKE_CHALLENGE_SIZE);       // Prijata vyzva
    crypto_blake2b_update(&ctx, server_nonce, SAKE_NONCE_SERVER_SIZE); // Server nonce pre jedinecnost
    crypto_blake2b_final(&ctx, response);                              // Vytvorenie odpovede na vyzvu
    crypto_wipe(&ctx, sizeof(ctx));                                    // Bezpecne vymazanie pamate

    print_hex("Computed response: ", response, SAKE_RESPONSE_SIZE);
    return 0;
}

// Overenie odpovede na vyzvu
// Server overi ci klient pozna spravny kluc porovnanim odpovede
int verify_response(const uint8_t *response, const uint8_t *auth_key,
                    const uint8_t *challenge, const uint8_t *server_nonce)
{
    uint8_t expected_response[SAKE_RESPONSE_SIZE]; // Miesto pre ocakavanu odpoved

    // Vypocet ocakavanej odpovede rovnakym algoritmom
    compute_response(expected_response, auth_key, challenge, server_nonce);

    // Porovnanie prijatej a vypocitanej odpovede pomocou konstantneho casu
    if (crypto_verify32(expected_response, response) != 0)
    {
        fprintf(stderr, MSG_SAKE_AUTH_FAILED); // Vypis chyby pri neuspesnej autentizacii
        return -1;
    }

    printf(MSG_SAKE_AUTH_SUCCESS); // Hlasenie o uspesnej autentizacii
    return 0;
}

// Odvodenie kluca relacie z hlavneho kluca a nonce hodnot
// Vytvara unikatny relacny kluc pre kazdu komunikaciu
void derive_session_key(uint8_t *session_key, const uint8_t *master_key,
                        const uint8_t *client_nonce, const uint8_t *server_nonce)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, SESSION_KEY_SIZE);
    crypto_blake2b_update(&ctx, master_key, KEY_SIZE);                                                    // Hlavny kluc ako zaklad
    crypto_blake2b_update(&ctx, client_nonce, SAKE_NONCE_CLIENT_SIZE);                                    // Klientske nonce
    crypto_blake2b_update(&ctx, server_nonce, SAKE_NONCE_SERVER_SIZE);                                    // Serverove nonce
    crypto_blake2b_update(&ctx, (const uint8_t *)SAKE_DERIV_SESSION_TAG, strlen(SAKE_DERIV_SESSION_TAG)); // Tag pre separaciu
    crypto_blake2b_final(&ctx, session_key);                                                              // Vytvorenie relacneho kluca
    crypto_wipe(&ctx, sizeof(ctx));                                                                       // Bezpecne vymazanie kontextu

    print_hex("Derived session key: ", session_key, SESSION_KEY_SIZE);
}

// Evolucia klucov po vytvoreni relacie
// Zabezpecuje "forward secrecy" - ochrana predchadzajucich komunikacii pri kompromitacii aktualneho kluca
void evolve_keys(uint8_t *master_key, uint8_t *auth_key, uint64_t counter)
{
    // Ulozenie povodnych klucov pre neskor
    uint8_t old_master[KEY_SIZE];
    memcpy(old_master, master_key, KEY_SIZE);

    // Evolucia hlavneho kluca K pomocou hashu s pouzitim countera pre jedinecnost
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, KEY_SIZE);
    crypto_blake2b_update(&ctx, master_key, KEY_SIZE);
    crypto_blake2b_update(&ctx, (uint8_t *)&counter, SAKE_KEY_COUNTER_SIZE);                      // Pridanie pocitadla pre jedinecnost
    crypto_blake2b_update(&ctx, (const uint8_t *)SAKE_DERIV_KEY_TAG, strlen(SAKE_DERIV_KEY_TAG)); // Tag pre separaciu
    crypto_blake2b_final(&ctx, master_key);                                                       // Novy hlavny kluc

    // Odvodenie noveho autentizacneho kluca K' z noveho hlavneho kluca
    derive_authentication_key(auth_key, master_key);

    // Bezpecne vymazanie stareho kluca z pamate
    secure_wipe(old_master, KEY_SIZE);
    crypto_wipe(&ctx, sizeof(ctx));
}

// Inicializacia struktury retazca klucov pre SAKE
// Vytvori pociatocnu sadu klucov z hlavneho kluca
void sake_init_key_chain(sake_key_chain_t *chain, const uint8_t *master_key, int is_initiator)
{
    // Kopirovanie hlavneho kluca
    memcpy(chain->master_key, master_key, KEY_SIZE);

    // Nastavenie epochy na nulu (zaciatocny stav)
    chain->epoch = 0;
    chain->is_initiator = is_initiator;

    // Odvodenie aktualneho autentizacneho kluca K'_0
    derive_authentication_key(chain->auth_key_curr, chain->master_key);

    // Ak je to iniciator, musime vytvorit aj dalsi autentizacny kluc K'_1
    if (is_initiator)
    {
        // Vytvorenie docasnej kopie pre evoluciu
        uint8_t temp_master[KEY_SIZE];
        uint8_t temp_auth[KEY_SIZE];
        memcpy(temp_master, chain->master_key, KEY_SIZE);
        memcpy(temp_auth, chain->auth_key_curr, KEY_SIZE);

        // Evolucia klucov pre epoch 1
        evolve_keys(temp_master, temp_auth, 1);

        // Ulozenie autentizacneho kluca pre epoch 1
        memcpy(chain->auth_key_next, temp_auth, KEY_SIZE);

        // Pre prvu inicializaciu, predchadzajuce a aktualne autentizacne kluce su rovnake
        memcpy(chain->auth_key_prev, chain->auth_key_curr, KEY_SIZE);

        // Vymazanie docasnych klucov
        secure_wipe(temp_master, KEY_SIZE);
        secure_wipe(temp_auth, KEY_SIZE);
    }
    else
    {
        // Pre responder staci inicializovat aktualny autentizacny kluc
        memcpy(chain->auth_key_prev, chain->auth_key_curr, KEY_SIZE);
        memcpy(chain->auth_key_next, chain->auth_key_curr, KEY_SIZE);
    }

    print_hex("Initialized chain with master key: ", chain->master_key, KEY_SIZE);
    print_hex("Initial auth_key_curr: ", chain->auth_key_curr, KEY_SIZE);
    if (is_initiator)
    {
        print_hex("Initial auth_key_next: ", chain->auth_key_next, KEY_SIZE);
    }
}

// Aktualizacia retazca klucov
// Posunie kluce v retazci o jeden epoch dopredu
void sake_update_key_chain(sake_key_chain_t *chain)
{
    // Inicializacia docasnych premennych
    uint8_t temp_master[KEY_SIZE];
    uint8_t temp_auth[KEY_SIZE];

    if (chain->is_initiator)
    {
        // Pre initiatora udrzujeme tri autentizacne kluce

        // Posun autentizacnych klucov (predchadzajuci <- aktualny <- nasledujuci)
        memcpy(chain->auth_key_prev, chain->auth_key_curr, KEY_SIZE);
        memcpy(chain->auth_key_curr, chain->auth_key_next, KEY_SIZE);

        // Evolucia master kluca a vypocet noveho nasledujuceho autentizacneho kluca
        memcpy(temp_master, chain->master_key, KEY_SIZE);

        // Vypocet noveho master kluca pre nasledujucu epochu (j+1)
        crypto_blake2b_ctx ctx;
        crypto_blake2b_init(&ctx, KEY_SIZE);
        crypto_blake2b_update(&ctx, chain->master_key, KEY_SIZE);
        uint64_t next_epoch = chain->epoch + 1;
        crypto_blake2b_update(&ctx, (uint8_t *)&next_epoch, SAKE_KEY_COUNTER_SIZE);
        crypto_blake2b_update(&ctx, (const uint8_t *)SAKE_DERIV_KEY_TAG, strlen(SAKE_DERIV_KEY_TAG));
        crypto_blake2b_final(&ctx, temp_master);

        // Odvodenie nasledujuceho autentizacneho kluca K'_(j+1)
        derive_authentication_key(chain->auth_key_next, temp_master);

        // Aktualizacia master kluca na aktualnu epochu
        crypto_blake2b_ctx ctx2;
        crypto_blake2b_init(&ctx2, KEY_SIZE);
        crypto_blake2b_update(&ctx2, chain->master_key, KEY_SIZE);
        crypto_blake2b_update(&ctx2, (uint8_t *)&chain->epoch, SAKE_KEY_COUNTER_SIZE);
        crypto_blake2b_update(&ctx2, (const uint8_t *)SAKE_DERIV_KEY_TAG, strlen(SAKE_DERIV_KEY_TAG));
        crypto_blake2b_final(&ctx2, chain->master_key);

        crypto_wipe(&ctx, sizeof(ctx));
        crypto_wipe(&ctx2, sizeof(ctx2));
    }
    else
    {
        // Pre respondera udrzujeme len aktualnu sadu klucov
        // Evolucia master kluca
        crypto_blake2b_ctx ctx;
        crypto_blake2b_init(&ctx, KEY_SIZE);
        crypto_blake2b_update(&ctx, chain->master_key, KEY_SIZE);
        crypto_blake2b_update(&ctx, (uint8_t *)&chain->epoch, SAKE_KEY_COUNTER_SIZE);
        crypto_blake2b_update(&ctx, (const uint8_t *)SAKE_DERIV_KEY_TAG, strlen(SAKE_DERIV_KEY_TAG));
        crypto_blake2b_final(&ctx, chain->master_key);

        // Odvodenie noveho autentizacneho kluca
        derive_authentication_key(chain->auth_key_curr, chain->master_key);

        // Aktualizujeme vsetky auth kluce
        memcpy(chain->auth_key_prev, chain->auth_key_curr, KEY_SIZE);
        memcpy(chain->auth_key_next, chain->auth_key_curr, KEY_SIZE);

        crypto_wipe(&ctx, sizeof(ctx));
    }

    // Zvysenie epochy
    chain->epoch++;

    // Vymazanie docasnych premennych
    secure_wipe(temp_master, KEY_SIZE);
    secure_wipe(temp_auth, KEY_SIZE);

    printf("Updated key chain to epoch %llu\n", (unsigned long long)chain->epoch);
    print_hex("New master key: ", chain->master_key, KEY_SIZE);
    print_hex("New auth_key_curr: ", chain->auth_key_curr, KEY_SIZE);
    if (chain->is_initiator)
    {
        print_hex("New auth_key_prev: ", chain->auth_key_prev, KEY_SIZE);
        print_hex("New auth_key_next: ", chain->auth_key_next, KEY_SIZE);
    }
}
