# Symmetric-key Authenticated Key Exchange (SAKE) Protocol

## Implementacia protokolu

Tento dokument podrobne popisuje implementaciu protokolu SAKE v projekte pre zabezpeceny prenos suborov. SAKE protokol zabezpecuje vzajomnu autentifikaciu a vymenu klucov medzi klientom a serverom bez pouzitia asymetrickej kryptografie, cim poskytuje vysoku bezpecnost a zaroven odolnost voci post-kvantovym utokom.

## Popis Protokolu

SAKE je protokol pre autentifikovanu vymenu klucov pouzivajuci vylucne symetricke kryptograficke primitiva. Umoznuje dvom stranam, ktore zdielaju tajny kluc, vzajomne sa autentifikovat a vytvorit bezpecne spojenie.

## Struktura Key Chain

V implementacii sa vyuziva system "key chain" (retazec klucov):

1. **Master Key** - Hlavny kluc, ktory je zakladom celeho retazca klucov
2. **Authentication Key** - Kluc pre autentifikaciu odvodeny z Master Key
3. **Session Key** - Kluc pre sifrovanie komunikacie odvodeny z Master Key a nonce hodnot

Pre kazdy ucastnik sa udrziavaju:
- **auth_key_prev** - Predchadzajuci autentifikacny kluc
- **auth_key_curr** - Aktualny autentifikacny kluc
- **auth_key_next** - Nasledujuci autentifikacny kluc (pre plynulu rotaciu)
- **epoch** - Pocitadlo verzie kluca
- **is_initiator** - Tag, ci ide o iniciatora spojenia

## Klucove Komponenty

1. **Master Kluc** - Zdielany tajny kluc odvodeny z hesla pomocou Argon2i s velkostou 32 bajtov (256 bitov)
2. **Odvodzovaci Kluc (K)** - Pouziva sa na odvodenie relacnych klucov, aktualizovany pocas evolucii kluca
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
  - Pouziva hashovacie odvodzovanie BLAKE2b s predchadzajucim klucom ako vstupom

- **evolve_keys**:
  - Aktualizuje hlavny kluc K a autentifikacny kluc K'
  - Pouziva counter pre zabranenie opakovania klucov
  - Vstupmi su: povodny kluc K, hodnota pocitadla a tag "SAKE_K"

- **sake_update_key_chain**:
  - Posunie kluce v retazci o jednu epochu dopredu
  - Pre initiator aktualizuje vsetky tri autentifikacne kluce
  - Pre responder aktualizuje iba aktualny kluc

### 4. Overovanie synchronizacie klucov

- **generate_key_validation**:
  - Vytvara 16-bajtovy validacny kod pomocou BLAKE2b-16
  - Pouziva aktualne platny kluc ako vstup
  - Sluzi na overenie, ci obe strany maju rovnaky kluc po rotacii

- **sake_init_key_chain**:
  - Inicializuje strukturu retazca klucov pre SAKE
  - Nastavuje rozne spravanie pre initiator a responder
  - Pripravuje vsetky potrebne kluce pre autentifikaciu

## Podrobny Priebeh Protokolu

### 1. Inicializacia spojenia

```
Klient                              Server
  |                                   |
  | --- [Salt] ------------------>    | Klient generuje sol a posiela ju serveru
  |                                   |
  |                                   | Server odvodi master kluc K z hesla a prijatej soli
  |                                   |
  | <-- [KEYOK] -------------------   | Server potvrdzuje prijem soli
  |                                   |
```

### 2. SAKE Autentifikacia

```
Klient                              Server
  |                                   |
  | --- [Client_Nonce] ----------->   | Klient posiela nahodny nonce
  |                                   |
  |                                   | Server generuje vlastny nonce a challenge
  |                                   |
  | <-- [Server_Nonce][Challenge] --  | Server posiela nonce a challenge
  |                                   |
  | Klient vypocita odpoved           |
  |                                   |
  | --- [Response] --------------->   | Klient posiela odpoved
  |                                   |
  |                                   | Server overuje odpoved
  |                                   |
```

### 3. Ustanovenie session kluca a evolucia klucov

```
Klient                              Server
  |                                   |
  | Odvodenie session kluca           | Odvodenie session kluca
  | z master kluca K a nonce hodnot   | z master kluca K a nonce hodnot
  |                                   |
  | Evolucia master kluca             | Evolucia master kluca
  | K_(j) -> K_(j+1)                  | K_(j) -> K_(j+1)
  |                                   |
```

### 4. Rotacia klucov pocas prenosu

```
Klient                              Server
  |                                   |
  | --- [KEY_ROTATION_MARKER] ----->  | Signalizacia rotacie kluca
  |                                   |
  | <-- [KEY_ROTATION_ACK] -------    | Potvrdenie pripravenosti
  |                                   |
  | --- [New_Client_Nonce] ------->   | Novy klient nonce
  |                                   |
  | <-- [New_Server_Nonce] -------    | Novy server nonce
  |                                   |
  | --- [KEY_ROTATION_VALIDATE] -->   | Signal pre validaciu klucov
  |                                   |
  | Odvodi novy session kluc          | Odvodi novy session kluc
  |                                   |
  | --- [Validation_Code] -------->   | Odoslanie validacneho kodu
  |                                   |
  |                                   | Overenie validacneho kodu
  |                                   |
  | <-- [KEY_ROTATION_READY] ------   | Potvrdenie synchronizacie
  |                                   |
```

## Bezpecnostne Vlastnosti a Implementovane Ochrany

### 1. Forward Secrecy 
- Po evolucii klucov nie je mozne odvodit predchadzajuce kluce
- Evolucia je jednosmerna, co zabezpecuje, ze ani pri kompromitacii aktualneho kluca nie su ohrozene predchadzajuce komunikacie

### 2. Vzajomna Autentifikacia 
- Challenge-response mechanizmus vyuziva zdielany tajny kluc
- Autentifikacia prebieha bez prezradenia tajneho kluca

### 3. Ochrana Proti Replay Utokom 
- Jedinecne nonce hodnoty pre kazdu relaciu
- Rotacia klucov pocas prenosu

### 4. Ochrana Proti Timing Utokom
- Pouzivanie konstantno-casovych porovnavacich funkcii (`crypto_verify32`)
- Bezpecne vymazanie pamate po pouziti (`secure_wipe`)
- Ziadne podmienene vetvenia zavisle na tajnych datach

### 5. Separacia Klucov 
- Rozne kluce pre rozne ucely s vhodnou separaciou domen
- Pouzitie tagov pre odlisenie odvodzovania klucov

### 6. Ochrana integrity
- Vyuzitie AEAD (Authenticated Encryption with Associated Data)
- Overovanie integrity dat pomocou MAC tagov
- Validacia synchronizacie klucov

## Vyhody Implementacie

1. **Post-kvantova bezpecnost** - Pouziva len symetricke kryptograficke primitiva, ktore su odolne voci znamym kvantovym algoritmom
2. **Vysoky vykon** - Symetricka kryptografia je rychlejsia ako asymetricka
3. **Nizka pamatova narocnost** - Vhodne pre obmedzene zariadenia
4. **Pravidelna rotacia klucov** - Obmedzuje riziko pri kompromitacii kluca
5. **Autorizacia a autentifikacia** - Zabudovana do protokolu bez potreby dodatocnych mechanizmov
6. **Robustny key management** - Systematicka sprava klucov s podporou evolucie

## Pouzite Kryptograficke Primitiva

Protokol je implementovany pomocou kniznice Monocypher 4.0.2 s tymito algoritmami:
- **BLAKE2b** - Moderna kryptograficka hashovacia funkcia pre odvodzovanie klucov a MAC
- **ChaCha20-Poly1305** - AEAD sifrovaci algoritmus pre sifrovanie s autentifikaciou
- **Argon2i** - Funkcia na odvodzovanie klucov z hesiel odolna voci hardverovym utokom
- **Konstantno-casove porovnavacie funkcie** - Pre bezpecne porovnavanie klucov a MAC hodnot