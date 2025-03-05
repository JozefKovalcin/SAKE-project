Zabezpeceny prenos suborov cez SAKE protokol

Tento projekt implementuje system pre zabezpeceny prenos suborov cez TCP/IP siet s vyuzitim SAKE protokolu (Symmetric-key Authenticated Key Exchange). Program zabezpecuje end-to-end sifrovanie s autentifikaciou, perfect forward secrecy, a rotaciu klucov pocas prenosu.

## Bezpecnostne prvky

### Sifrovanie a autentifikacia
- ChaCha20-Poly1305 pre sifrovanie s autentifikaciou
- Unikatny nonce pre kazdy blok dat
- MAC (Message Authentication Code) pre integritu dat
- Kontrola podvrhnutia alebo upravy dat

### Manazment klucov
- Argon2id pre bezpecnu derivaciu klucov z hesiel
- Symetricka autentifikacia medzi klientom a serverom
- Automaticka rotacia klucov pocas dlhych prenosov
- Validacia synchronizacie klucov medzi klientom a serverom

### Sietova bezpecnost
- Timeouty pre vsetky sietove operacie
- Detekcia odpojenia pomocou keepalive
- Kontrola velkosti blokov proti preteceniu
- Spolahlivy prenos s retransmisiou
- Synchronizacia a potvrdenia prenosov pomocou custom protokolu

## SAKE Protokol

SAKE (Symmetric-key Authenticated Key Exchange) poskytuje:

1. Vzajomna autentifikacia medzi klientom a serverom
2. Ustanovenie session kluca
3. Forward secrecy pomocou evolucie klucov

### Priebeh protokolu

1. Klient a server odvodia master kluc K zo zdielaneho hesla pomocou Argon2
2. Obe strany odvodia autentifikacny kluc K' z master kluca K
3. Klient posle nahodny nonce serveru
4. Server vygeneruje vyzvu zalozenu na K', nonce klienta a vlastnom nahodnom nonce
5. Klient vypocita odpoved na vyzvu
6. Server overi odpoved, cim autentifikuje klienta
7. Obe strany odvodia session kluc z master kluca a oboch nonce hodnot
8. Prebieha evolucia klucov pre zabezpecenie forward secrecy

## Hlavne komponenty

### Server (server.c)
- Pocuva na TCP porte 8080
- Autentifikuje prichadzajuce spojenia
- Desifruje a overuje prijate data
- Uklada subory s prefixom "received_"
- Synchronizuje rotaciu klucov s klientom

### Klient (client.c)
- Zobrazuje dostupne lokalne subory
- Sifruje a fragmentuje subory na bloky
- Synchronizuje rotaciu klucov so serverom
- Zobrazuje progres prenosu

### Kryptograficke funkcie (crypto_utils.c, crypto_utils.h)
- Generovanie nahodnych hodnot
- Derivacia a rotacia klucov
- Implementacia SAKE protokolu
- Validacia klucov
- Generovanie a verifikacia MAC tagov

## Poziadavky
- C kompilator (GCC/MinGW)
- Monocypher 4.0.2
- Make

## Kompilacia
```bash
# Linux
make all

# Windows (MinGW)
mingw32-make all alebo .\build.bat
```

## Pouzitie
Spustenie servera:
```bash
./server
```

Spustenie klienta:
```bash
./client
```

## Priebeh komunikacie:
1. **Vytvorenie zabezpeceneho spojenia**:
   - Inicializacia SAKE protokolu
   - Vymena nonce hodnot
   - Vzajomna autentifikacia cez zdielane heslo
   - Vytvorenie session kluca

2. **Prenos suboru**:
   - Klient zobrazi dostupne lokalne subory
   - Pouzivatel vyberie subor na prenos
   - Subor je fragmentovany na bloky
   - Kazdy blok je samostatne sifrovany s unikatnym nonce
   - Server overuje integritu a desifruje bloky
   - Prijaty subor je ulozeny s prefixom "received_"

3. **Rotacia klucov**:
   - Po stanovenom pocte blokov sa iniciuje rotacia
   - Obe strany synchronne odvodia novy kluc
   - Prebehne validacia spravnosti rotacie
   - Prenos pokracuje s novym klucom

## Chybove stavy
Program obsahuje robustnu detekciu a spracovanie chyb:
- Timeout pri sietovych operaciach
- Neuspesna autentifikacia
- Corrupted alebo manipulovane data
- Neuspesna synchronizacia klucov
- Chyby pri praci so subormi

## Bezpecnostne poznamky
Vsetky citlive data su okamzite vymazane z pamate po pouziti

Perfect forward secrecy zabezpecuje ze:
- Kompromitacia dlhodobeho kluca neohrozuje minule prenosy
- Kazde spojenie pouziva nove nahodne kluce
- Historia komunikacie je chranena aj pri ziskani aktualnych klucov

Pravidelna rotacia klucov:
- Limituje mnozstvo dat sifrovanych jednym klucom
- Poskytuje post-compromise security
- Synchronne prebieha na oboch stranach

Ochrana proti MitM utokom:
- Autentifikacia pomocou zdielaneho hesla
- Validacia integrity pomocou MAC
- Overovanie synchronizacie klucov

## Vycistenie projektu
```bash
# Linux
make clean

# Windows
mingw32-make clean
```

## Limity a mozne vylepsenia
- Implementacia threadov pre paralelne spracovanie
- Podpora pre viacero sucasnych klientov
- Komprimacia pred sifrovanim
- Obnovenie prerusenych prenosov
- GUI rozhranie