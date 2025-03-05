/*******************************************************************************
 * Program:    SAKE (Symmetric Authenticated Key Exchange) Protocol
 * Subor:      sake.h
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      05-03-2025
 * 
 * Popis: 
 *     Tento subor obsahuje funkcie pre implementaciu SAKE protokolu:
 *     - Autentifikaciu na zaklade zdielanych tajomstiev
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

#include <stdint.h> // Kniznica pre datove typy (uint8_t, uint32_t)
#include "constants.h" // Definicie konstant pre program
#include "monocypher.h" // Pre Monocypher kryptograficke funkcie

// SAKE protokol - funkcie pre autentifikáciu a výmenu kľúčov
void derive_authentication_key(uint8_t *auth_key,     // Odvodenie autentifikacneho kluca K' z hlavneho kluca K
                              const uint8_t *master_key);

void generate_challenge(uint8_t *challenge,          // Generovanie vyzvy pre autentifikaciu
                       uint8_t *server_nonce,
                       const uint8_t *auth_key,
                       const uint8_t *client_nonce);

int compute_response(uint8_t *response,              // Vypocet odpovede na vyzvu
                    const uint8_t *auth_key,
                    const uint8_t *challenge,
                    const uint8_t *server_nonce);

int verify_response(const uint8_t *response,         // Overenie odpovede na vyzvu
                   const uint8_t *auth_key,
                   const uint8_t *challenge,
                   const uint8_t *server_nonce);

void derive_session_key(uint8_t *session_key,        // Odvodenie kluca relacie z hlavneho kluca a nonce
                        const uint8_t *master_key,
                        const uint8_t *client_nonce,
                        const uint8_t *server_nonce);

void evolve_keys(uint8_t *master_key,               // Evolucia klucov po vytvoreni relacie
                uint8_t *auth_key,
                uint64_t counter);

#endif // SAKE_H
