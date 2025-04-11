/********************************************************************************
 * Program:    Platformovo-nezavisle funkcie pre kryptograficky system
 * Subor:      platform.c
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      05-03-2025
 *
 * Popis:
 *     Implementacia platformovo-nezavislych operacii:
 *     - Generovanie kryptograficky bezpecnych nahodnych cisel
 *     - Bezpecne nacitanie hesla od uzivatela
 *
 * Zavislosti:
 *     - platform.h (deklaracie funkcii)
 *     - constants.h (konstanty programu)
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "platform.h"
#include "constants.h"

// Bezpecnostne funkcie
// Generovanie kryptograficky bezpecnych nahodnych cisel
// Pouziva systemove generatory (BCrypt na Windows, getrandom na Linuxe)
int platform_generate_random_bytes(uint8_t *buffer, size_t size)
{
    if (!buffer || size == 0)
    {
        fprintf(stderr, "Error: Invalid parameters for random number generation\n");
        return -1;
    }

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlgorithm;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        fprintf(stderr, "Error: Failed to open algorithm provider for random generation\n");
        return -1;
    }

    status = BCryptGenRandom(hAlgorithm, buffer, (ULONG)size, 0);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    if (!BCRYPT_SUCCESS(status))
    {
        fprintf(stderr, "Error: Failed to generate random bytes\n");
        return -1;
    }
#else
    ssize_t result = getrandom(buffer, size, 0);
    if (result < 0 || (size_t)result != size)
    {
        fprintf(stderr, "Error: Failed to generate random bytes: %s\n", strerror(errno));
        return -1;
    }
#endif

    return 0;
}

// Funkcia na bezpecne nacitanie hesla bez jeho zobrazenia na obrazovke
// Pouziva rozne implementacie podla platformy (Windows / Linux)
// Parametere:
//   - prompt: Text vyzvy pre pouzivatela
// Navratova hodnota:
//   - Ukazovatel na staticky buffer obsahujuci zadane heslo
char *platform_getpass(const char *prompt)
{
    // Staticky buffer na ulozenie hesla, umoznuje volanie funkcie bez alokacie pamate
    static char password[256];
    // Zobrazenie vyzvy pre pouzivatela
    fprintf(stdout, "%s", prompt);
    fflush(stdout);

#ifdef _WIN32
    // Implementacia pre Windows platformu
    size_t i = 0;
    int c;
    // Nacitavame znaky kym nenastane koniec riadku, EOF alebo zaplnenie bufferu
    while ((c = _getch()) != '\r' && c != EOF && i < sizeof(password) - 1)
    {
        if (c == '\b')
        { // Spracovanie klavesy Backspace
            if (i > 0)
            {
                i--;
                printf("\b \b"); // Vymazanie znaku z obrazovky
            }
        }
        else
        {
            password[i++] = c;
            printf("*"); // Zobrazenie hviezdicky namiesto skutocneho znaku
        }
    }
    password[i] = '\0'; // Ukoncenie retazca
    printf("\n");
#else
    // Implementacia pre Linux/Unix platformy
    FILE *fp = fopen("/dev/tty", "r+");
    if (!fp)
    {
        fp = stdin; // Zaloha na stdin ak /dev/tty nie je dostupny
    }

    // Vypnutie zobrazovania znakov (echo)
    int ret = system("stty -echo");
    if (ret != 0)
    {
        fprintf(stderr, "Warning: Failed to disable terminal echo\n");
    }

    if (fgets(password, sizeof(password), fp) != NULL)
    {
        // Odstranenie znaku noveho riadku
        size_t len = strlen(password);
        if (len > 0 && password[len - 1] == '\n')
        {
            password[len - 1] = '\0';
        }
    }
    else
    {
        password[0] = '\0'; // Prazdny retazec v pripade chyby
    }

    // Obnovenie zobrazovania znakov
    ret = system("stty echo");
    if (ret != 0)
    {
        fprintf(stderr, "Warning: Failed to enable terminal echo\n");
    }
    printf("\n");

    // Zatvorenie suboru ak to nebol stdin
    if (fp != stdin)
    {
        fclose(fp);
    }
#endif

    return password; // Vratenie ukazovatela na heslo
}
