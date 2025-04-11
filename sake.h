/*******************************************************************************
 * Program:    SAKE (Symmetric Authenticated Key Exchange) Protocol
 * Subor:      sake.h
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      05-03-2025
 *
 * Popis:
 *     Tento subor obsahuje funkcie pre implementaciu SAKE protokolu:
 *     - Autentizaciu na zaklade zdielanych tajomstiev
 *     - Odvodzovanie relacnych klucov
 *     - Pravidelnu rotaciu klucov pocas prenosu
 *     - Bezpecne odvodzovanie relacnych klucov s forward secrecy
 *
 * Zavislosti:
 *     - Monocypher 4.0.2 (sifrovacie algoritmy)
 *     - constants.h (konstanty programu)
 ******************************************************************************/

#ifndef SAKE_H
#define SAKE_H

#include <stdint.h>     // Kniznica pre datove typy (uint8_t, uint32_t)
#include "constants.h"  // Definicie konstant pre program
#include "monocypher.h" // Pre Monocypher kryptograficke funkcie

// Struktura pre uchovavanie retazca klucov pre SAKE
typedef struct
{
    uint8_t master_key[32];    // Aktualny master key K_j
    uint8_t auth_key_prev[32]; // Predosly authentication key K'_(j-1)
    uint8_t auth_key_curr[32]; // Aktualny authentication key K'_j
    uint8_t auth_key_next[32]; // Dalsi authentication key K'_(j+1)
    uint64_t epoch;            // Aktualne cislo j
    int is_initiator;          // Iniciator = 0; Responder = 1
} sake_key_chain_t;

// SAKE protokol - funkcie pre autentizaciu a vymenu klucov
void derive_authentication_key(uint8_t *auth_key, // Odvodenie autentizacneho kluca K' z hlavneho kluca K
                               const uint8_t *master_key);

void generate_challenge(uint8_t *challenge, // Generovanie vyzvy pre autentizaciu
                        uint8_t *server_nonce,
                        const uint8_t *auth_key,
                        const uint8_t *client_nonce);

int compute_response(uint8_t *response, // Vypocet odpovede na vyzvu
                     const uint8_t *auth_key,
                     const uint8_t *challenge,
                     const uint8_t *server_nonce);

int verify_response(const uint8_t *response, // Overenie odpovede na vyzvu
                    const uint8_t *auth_key,
                    const uint8_t *challenge,
                    const uint8_t *server_nonce);

void derive_session_key(uint8_t *session_key, // Odvodenie kluca relacie z hlavneho kluca a nonce
                        const uint8_t *master_key,
                        const uint8_t *client_nonce,
                        const uint8_t *server_nonce);

void sake_init_key_chain(sake_key_chain_t *chain, const uint8_t *master_key, int is_initiator); // Inicializacia retazca klucov pre SAKE

void sake_update_key_chain(sake_key_chain_t *chain); // Aktualizacia retazca klucov

void evolve_keys(uint8_t *master_key, // Evolucia klucov po vytvoreni relacie
                 uint8_t *auth_key,
                 uint64_t counter);

#endif // SAKE_H
