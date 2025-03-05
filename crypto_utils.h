/*******************************************************************************
 * Program:    Kryptograficke nastroje pre zabezpeceny prenos
 * Subor:      crypto_utils.h
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      05-03-2025
 * 
 * Popis: 
 *     Tento subor obsahuje funkcie pre:
 *     - Bezpecne generovanie nahodnych cisel pre nonce a salt
 *     - Vytvaranie klucov z hesiel pomocou Argon2
 *     - Bezpecne mazanie citlivych dat
 *     - Rotaciu klucov
 * 
 * Zavislosti:
 *     - Monocypher 4.0.2 (sifrovacie algoritmy)
 *     - constants.h (konstanty programu)
 *     - sake.h (pre SAKE protokol)
 *     - platform.h (platform-specificke funkcie)
 ******************************************************************************/

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h> // Kniznica pre datove typy (uint8_t, uint32_t)

#include "monocypher.h"  // Pre Monocypher kryptograficke funkcie
#include "constants.h"    // Definicie konstant pre program
#include "sake.h"         // Pre SAKE protokol funkcie
#include "platform.h"     // Pre funkcie specificke pre operacny system

// Pomocne funkcie
void print_hex(const char *label, uint8_t *data, int len);  // Vypise data v citatelnej forme pre kontrolu

// Zakladne kryptograficke funkcie
void generate_random_bytes(uint8_t *buffer, size_t size);  // Vytvori bezpecne nahodne cisla

// Funkcie pre pracu s heslami
int derive_key_server(const char *password, const uint8_t *received_salt,  // Server: Vytvori kluc z hesla a prijatej soli
                     uint8_t *key, uint8_t *salt);

int derive_key_client(const char *password, uint8_t *key, uint8_t *salt);  // Klient: Vytvori kluc z hesla a novej soli

// Funkcie pre bezpecnost spojenia
void rotate_key(uint8_t *current_key,    // Vytvori novy kluc z existujuceho pre lepsiu bezpecnost
               const uint8_t *previous_key);

void secure_wipe(void *data, size_t size);  // Bezpecne vymaze citlive data z pamate

// Overovanie klucov
void generate_key_validation(uint8_t *validation,   // Vytvori kontrolny kod pre overenie kluca
                           const uint8_t *key);

#endif // CRYPTO_UTILS_H