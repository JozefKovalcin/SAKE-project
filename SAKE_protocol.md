# Symmetric-key Authenticated Key Exchange (SAKE) Protocol

## Implementacia protokolu

SAKE protokol zabezpecuje vzajomnu autentifikaciu a vymenu klucov medzi klientom a serverom bez pouzitia asymetrickej kryptografie, cim poskytuje vysoku bezpecnost a zaroven odolnost voci post-kvantovym utokom.

## Popis Protokolu

SAKE je protokol pre autentifikovanu vymenu klucov pouzivajuci vylucne symetricke kryptograficke primitiva. Umoznuje dvom stranam, ktore zdielaju tajny kluc, vzajomne sa autentifikovat a vytvorit bezpecne spojenie.

## Klucove Komponenty

1. **Master Kluc** - Zdielany tajny kluc odvodeny z hesla pomocou Argon2i s velkostou 32 bajtov (256 bitov)
2. **Derivacny Kluc (K)** - Pouziva sa na odvodenie relacnych klucov, aktualizovany pocas evolucii kluca
3. **Autentifikacny Kluc (K')** - Odvodeny z K pomocou BLAKE2b, pouziva sa na autentifikaciu sprav
4. **Pocitadlo Verzii** - Pre sledovanie evolucie klucov (8-bajtova hodnota)
5. **Nonce hodnoty** - Nahodne hodnoty na strane klienta (16 bajtov) a servera (16 bajtov)

## Implementacne Detaily Funkcii

### 1. Odvodzovanie klucov

- **derive_key_client/derive_key_server**: 
  - Pouzivaju Argon2i s parametrami: 65536 KB pamati, 3 iteracie, 1 paralelny vypocet
  - Sol ma velkost 16 bajtov a je generovana nahodne
  - Vysledny kluc ma velkost 32 bajtov (256 bitov)

- **derive_authentication_key**: 
  - Vytvara autentifikacny kluc K' z hlavneho kluca K
  - Pouziva BLAKE2b-256 s jedinecnym oddelovacim tagom "SAKE_K_AUTH"

### 2. Challenge-Response Autentifikacia

- **generate_challenge**:
  - Server generuje nahodny nonce (16 bajtov)
  - Vytvara challenge pomocou BLAKE2b-32 zo vstupov: K', nonce klienta a nonce servera

- **compute_response**:
  - Klient vypocita odpoved pomocou BLAKE2b-32 zo vstupov: K', challenge a nonce servera
  - Odpoved ma velkost 32 bajtov

- **verify_response**:
  - Server verifikuje odpoved klienta pomocou rovnakeho vypoctu a konstant-case porovnania
  - Pouziva funkciu crypto_verify32 pre bezpecne porovnanie odpovedajuce konstatny cas

### 3. Relacny kluc a rotacia klucov

- **derive_session_key**:
  - Vytvara relacny kluc velkosti 32 bajtov pomocou BLAKE2b
  - Vstupmi su: hlavny kluc K, nonce klienta, nonce servera a separacny tag "SAKE_SESSION"
  - Tento kluc sa pouziva pre ChaCha20-Poly1305 sifrovanie

- **rotate_key**:
  - Implementuje rotaciu klucov pocas prenosu dat (po kazdych 1024 blokoch)
  - Pouziva hashovacie derivovanie BLAKE2b s predchadzajucim klucom ako vstupom

- **evolve_keys**:
  - Aktualizuje hlavny kluc K a autentifikacny kluc K'
  - Pouziva counter pre zabranenie opakovania klucov
  - Vstupmi su: povodny kluc K, hodnota pocitadla a tag "SAKE_K"

### 4. Overovanie synchronizacie klucov

- **generate_key_validation**:
  - Vytvara 16-bajtovy validacny kod pomocou BLAKE2b-16
  - Pouziva aktualne platny kluc ako vstup
  - Sluzi na overenie, ci obe strany maju rovnaky kluc po rotacii

## Podrobny Priebeh Protokolu

1. **Inicializacia spojenia**:
   - Klient odvodzuje kluc z hesla a generuje sol pomocou `derive_key_client`
   - Klient posiela sol serveru
   - Server odvodzuje rovnaky kluc z rovnakeho hesla pomocou `derive_key_server`
   - Z hlavneho kluca sa odvodzuje autentifikacny kluc pomocou `derive_authentication_key`

2. **SAKE Autentifikacia**:
   - Klient generuje nahodny nonce (16 bajtov) a posiela ho serveru
   - Server generuje vlastny nonce (16 bajtov) a challenge (32 bajtov) pomocou `generate_challenge`
   - Server posiela svoj nonce a challenge klientovi
   - Klient vypocita odpoved pomocou `compute_response` a posiela ju serveru
   - Server overuje odpoved pomocou `verify_response`

3. **Vytvorenie zabezpeceneho spojenia**:
   - Po uspesnej autentifikacii obe strany odvodzuju relacny kluc pomocou `derive_session_key`
   - Server posiela potvrdenie o uspesnej autentifikacii
   - Obe strany aktualizuju hlavny kluc a autentifikacny kluc pomocou `evolve_keys`

4. **Zabezpeceny prenos dat**:
   - Data su sifrovane pomocou ChaCha20-Poly1305 s relacnym klucom
   - Kazdy blok ma jedinecny nonce a autentifikacny tag
   - Po kazdych 1024 blokoch sa kluc rotuje pomocou `rotate_key`
   - Po rotacii kluca sa validuje jeho synchronizacia pomocou `generate_key_validation`

5. **Ukoncenie spojenia**:
   - Po dokonceni prenosu je odoslany marker konca suboru (chunk_size = 0)
   - Server potvrduje uspesne prijatie dat
   - Spojenie je bezpecne ukoncene a vsetky citlive data su vymazane z pamati pomocou `secure_wipe`

## Bezpecnostne Vlastnosti a Implementovane Ochrany

1. **Forward Secrecy** 
   - Evolucne aktualizacie klucov zabrania odvodeniu predoslych klucov z aktualnych
   - Funkcia `evolve_keys` zabezpecuje jednosmerne aktualizacie klucov

2. **Vzajomna Autentifikacia** 
   - Challenge-response mechanizmus overuje posiadanie zdielaneho kluca na oboch stranach
   - Server overuje odpoved klienta cez `verify_response`

3. **Ochrana Proti Replay Utokom** 
   - Jedinecne nahodne nonce hodnoty pre kazdu relaciu
   - Pravidelna rotacia klucov pocas prenosu dat

4. **Ochrana Proti Timing Utokom**
   - Pouzitie funkcie `crypto_verify32` pre porovnanie v konstantom case
   - Bezpecne vymazanie citlivych dat z pamati pomocou `secure_wipe`

5. **Separacia Klucov** 
   - Rozne kluce pre rozne ucely s vhodnou domenovou separaciou
   - Separacne tagy pre odlisenie roznych pouziti hashovacej funkcie

6. **Overenie Integrity Klucov**
   - Validacia synchronizacie klucov po rotacii pomocou `generate_key_validation`
   - Detekcia nezhody klucov a zabranenie pokracovaniu s nesynchornizovanymi klucmi

## Vyhody Implementacie

1. **Post-kvantova Bezpecnost** - Nepouziva asymetricku kryptografiu zranitelnu kvantovymi algoritmami
2. **Vysoka Vykonnost** - Symetricke algoritmy su rychlejsie ako asymetricke
3. **Nizka Pamatova Narocnost** - Vhodne pre obmedzene zariadenia
4. **Pravidelna Rotacia Klucov** - Obmedzuje mozny dopad kompromitacie kluca
5. **Detekcia Synchronizacnych Problemov** - Automaticka kontrola synchronizacie klucov

## Pouzite Kryptograficke Primitiva

Protokol je implementovany pomocou kniznice Monocypher 4.0.2 s tymito algoritmami:
- BLAKE2b pre vsetky operacie odvodzovania klucov, MAC a validacie
- ChaCha20-Poly1305 pre autentifikovane sifrovanie aplikacnych dat
- Argon2i pre pociatocne odvodenie klucov z hesla s ochranu proti utokom hrubou silou
