/********************************************************************************
 * Program:    Platformovo-nezavisle funkcie pre kryptograficky system
 * Subor:      platform.h
 * Autor:      Jozef Kovalcin
 * Verzia:     1.0.0
 * Datum:      05-03-2025
 *
 * Popis:
 *     Hlavickovy subor pre platformovo-nezavisle operacie:
 *     - Funkcie pre bezpecne generovanie nahodnych cisel
 *     - Platformovo nezavisle bezpecne nacitanie hesla
 *
 * Zavislosti:
 *     - Standardne C kniznice
 *     - constants.h (konstanty programu)
 *******************************************************************************/

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>
#include <stdint.h>

// Platformovo-specificke include subory
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <conio.h>
// Definicie pre Windows, ktore nie su dostupne
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
// Typy
typedef SOCKET socket_t;
typedef int socklen_t;
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#else
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/random.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
// Typy
typedef int socket_t;
#define INVALID_SOCKET_VALUE -1
#endif

// Bezpecnostne funkcie
int platform_generate_random_bytes(uint8_t *buffer, size_t size);
char *platform_getpass(const char *prompt);

#endif // PLATFORM_H
