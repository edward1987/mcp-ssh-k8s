# Ghid Complet de Utilizare — mcp-ssh-k8s

Acest ghid detaliază fiecare funcționalitate, ecran, flux de lucru și opțiune de configurare din aplicația **mcp-ssh-k8s**.

---

## Cuprins
1. [Pornirea și Inițializarea Aplicației](#1-pornirea-și-inițializarea-aplicației)
2. [Panoul de Administrare & Securitatea Vault-ului](#2-panoul-de-administrare--securitatea-vault-ului)
3. [Gestionarea Cheilor SSH](#3-gestionarea-cheilor-ssh)
4. [Gestionarea Hosturilor SSH](#4-gestionarea-hosturilor-ssh)
5. [Gestionarea Clusterelor Kubernetes](#5-gestionarea-clusterelor-kubernetes)
6. [Importul Automat (SSH Config, Termius CSV, Termius Desktop)](#6-importul-automat)
7. [Generarea și Gestionarea Tokenurilor MCP](#7-generarea-și-gestionarea-tokenurilor-mcp)
8. [Conectarea Clienților AI (Claude, Cursor, Windsurf)](#8-conectarea-clienților-ai)
9. [Integrarea cu ChatGPT prin OpenAI Secure Tunnel](#9-integrarea-cu-chatgpt-prin-openai-secure-tunnel)
10. [Fluxul de Aprobare Umană (Human-in-the-Loop)](#10-fluxul-de-aprobare-umană)
11. [Jurnalul de Audit](#11-jurnalul-de-audit)
12. [Setări Globale & Schimbarea Parolei Master](#12-setări-globale)
13. [Depanare & Întrebări Frecvente (FAQ)](#13-depanare--faq)

---

## 1. Pornirea și Inițializarea Aplicației

Aplicația rulează două servicii de rețea independente:
- **Portul 7777 (Admin Web UI)**: accesibil **exclusiv** pe `127.0.0.1` (loopback). Niciodată nu expune acest port în rețeaua locală sau internet!
- **Portul 7778 (Endpoint MCP)**: endpoint-ul HTTP Streamable (`http://127.0.0.1:7778/mcp`) folosit de AI cu antet de tip `Authorization: Bearer <token>`.

### Comenzi de pornire

```bash
# Instalare dependențe (la primul setup)
npm install

# Rulare în mod dezvoltare (reîncărcare automată)
npm run dev

# Rulare în mod producție (compilare + start)
npm run build
npm start
```

### Variabile de mediu opționale
- `ADMIN_PORT`: portul interfeței Web (implicit `7777`).
- `MCP_PORT`: portul serverului MCP (implicit `7778`).
- `MCP_BIND`: interfața de ascultare a MCP (implicit `127.0.0.1`).
- `MCP_SSH_DATA`: folderul de stocare pe disc (implicit `./data`).
- `KUBECTL_PATH`: calea către executabilul `kubectl` (implicit `kubectl` din PATH).

---

## 2. Panoul de Administrare & Securitatea Vault-ului

### Crearea Vault-ului (La prima accesare)
1. Deschide în browser: **[http://127.0.0.1:7777](http://127.0.0.1:7777)**.
2. La prima pornire, ți se cere să setezi **Parola Master** (minim 12 caractere).
3. În baza acestei parole, aplicația derivă cheia criptografică folosind `scrypt` ($N=2^{17}$, $r=8$, $p=1$) și inițializează fișierul criptat `data/vault.json` cu algoritmul **AES-256-GCM**.
4. **Important**: Nu uita această parolă! Dacă o pierzi, datele criptate din vault nu pot fi recuperate.

### Deblocare & Auto-Lock
- La redeschiderea browserului sau la expirarea sesiunii, ți se va solicita parola master pentru deblocare.
- În **Setări**, poți stabili un interval de **Auto-lock** (ex. 30 minute de inactivitate).
- Când vault-ul este blocat:
  - Nicio cheie privată sau parolă nu mai există în memoria RAM.
  - Orice apel venit din partea AI-ului pe portul MCP (7778) primește imediat codul HTTP `503 Service Unavailable` cu mesajul *"vault is locked"*.

---

## 3. Gestionarea Cheilor SSH

În tab-ul **Chei** poți adăuga cheile private folosite pentru autentificarea pe servere:

1. Apasă pe butonul **+ Cheie nouă**.
2. Completează câmpurile:
   - **Nume**: o etichetă de recunoaștere (ex. `prod-bastion`, `hetzner-deploy`).
   - **Cheie privată**: conținutul text al cheii private (fișierul fără extensia `.pub`, de regulă `id_ed25519` sau `id_rsa`), începând cu `-----BEGIN ... PRIVATE KEY-----`.
   - **Passphrase (opțional)**: dacă cheia privată a fost protejată cu parolă la generare.
3. **Validare automată**:
   - Sistemul respinge automat dacă încerci să lipești o cheie publică.
   - Normalizează sfârșiturile de linie CRLF/LF.
   - Detectează tipul cheii (`ed25519`, `rsa`, `ecdsa`) și îi afișează amprenta publică (*fingerprint*).

---

## 4. Gestionarea Hosturilor SSH

În tab-ul **Hosturi** poți configura serverele la care AI-ul poate avea acces.

### Adăugarea unui host
1. Apasă pe **+ Host nou**.
2. Completează datele:
   - **Nume**: identificatorul hostului (ex. `db-primary`, `web-api`). AI-ul va referenția serverul prin acest nume.
   - **Adresă / Hostname**: IP-ul sau domeniul serverului (ex. `10.0.0.12` sau `srv1.example.com`).
   - **Port**: implicit `22`.
   - **Utilizator**: utilizatorul SSH de conectare (ex. `root`, `ubuntu`, `deploy`).
   - **Autentificare**: alege între o cheie privată salvată în tab-ul Chei sau autentificare cu parolă.
   - **Grup (opțional)**: pentru organizare (ex. `Production`, `Staging/EU`).
   - **Taguri (opțional)**: etichete separate prin virgulă (ex. `docker, postgres, web`).

### Moduri de Securitate per Host
Fiecare host are un nivel de autonomie acordat AI-ului:

| Mod | Comportament | Când se recomandă |
| :--- | :--- | :--- |
| **`read-only`** | AI-ul poate rula **doar comenzi sigure de diagnosticare** (`uptime`, `free`, `df`, `ps`, `cat`, etc.). Sunt blocate metacaracterele de shell (`;`, `&&`, `\|`, redirecționări `>`), prevenind comenzile compuse. | Servere de producție sensibile, baze de date, unde vrei ca AI-ul doar să investigheze, fără risc de alterare. |
| **`approval`** | AI-ul poate propune **orice comandă**, însă execuția este suspendată până când aprobi manual comanda în tab-ul **Aprobări**. | Servere pe care AI-ul te asistă în mentenanță, dar vrei control total înainte de a rula comenzi de modificare. |
| **`free`** | AI-ul rulează comenzile direct, fără a aștepta confirmare umană. | Medii de testare / staging, containere locale, medii sandbox. |

### Acțiuni în masă & Monitorizare Reachability
- **Punctul de stare (Bulina colorată)**:
  - 🟢 **Verde**: serverul răspunde la verificarea de rețea (portul SSH este deschis).
  - 🔴 **Roșu**: serverul este offline sau portul este inaccesibil (AI-ul nu va încerca să se conecteze la el, evitând timeout-urile).
  - ⚪ **Gri**: host nou sau verificare în curs.
- **Selectare multiplă & Bulk Actions**:
  - Bifează căsuțele din stânga hosturilor sau alege un grup din dropdown.
  - Setează modul de siguranță pentru toate hosturile selectate simultan dintr-un singur click.
- **Butonul "Test"**: verifică instant conexiunea SSH completă (handshake, autentificare, rulare comandă simplă `uptime`).

---

## 5. Gestionarea Clusterelor Kubernetes

În tab-ul **Kubernetes** poți înrola clustere K8s pentru interogare și depanare prin unealta `kubectl`.

### Încărcarea fișierului `kubeconfig`
1. Apasă pe **+ Cluster nou**.
2. Completează numele clusterului (ex. `k8s-prod`, `k8s-dev`).
3. Selectează fișierul `kubeconfig` (în format YAML).
   > **Atenție: Fișierul trebuie să fie self-contained!**  
   > Clusterele nu pot accesa certificate stocate pe căi absolute locale de pe mașina de unde provine fișierul. Exportă un kubeconfig cu certificatele incluse în baza64 rulând:
   > ```bash
   > kubectl config view --raw --flatten > kubeconfig-export.yaml
   > ```
4. **Context & Namespace**:
   - Dacă lași contextul gol, se va folosi `current-context` din fișier.
   - Poți stabili un namespace implicit (ex. `default`, `production`).
5. **Alege Modul de Siguranță**:
   - `read-only`: AI-ul poate rula exclusiv verbe de citire: `get`, `describe`, `logs`, `top`, `explain`, `version`, `api-resources`, `events`, `auth can-i`, `rollout status`.  
     **Protecție automată**: Accesul la secrete (`get secrets`) este strict interzis în modul read-only! De asemenea, comenzile de urmărire continuă (`--watch`, `-f/--follow`) sunt blocate.
   - `approval`: comenzile de modificare (`apply`, `delete`, `scale`, `patch`, etc.) ajung în tab-ul Aprobări. Operatorul poate citi comanda și previzualiza manifestul YAML trimis la stdin (`-f -`).
   - `free`: AI-ul poate administra clusterul autonom.
6. **Bariere de securitate K8s universale (în toate modurile)**:
   - Nu se permite injectarea de flaguri care ar modifica identitatea sau fișierul kubeconfig: `--kubeconfig`, `--token`, `--server`, `--context`, `--as`.
   - Nu se permit comenzi care accesează fișiere locale de pe PC-ul tău: `-f <cale>`, `--from-file`, `-k`. Toate manifestele sunt transmise exclusiv prin stdin (`-f -`).

---

## 6. Importul Automat

Tab-ul **Import** îți permite să populezi rapid serverul cu conexiunile existente:

### 1. Din `~/.ssh/config`
- Detectează automat fișierul de configurare OpenSSH local.
- Importă directivele `Host`, `HostName`, `User`, `Port` și cheile referențiate prin `IdentityFile`.
- Poți debifa serverele pe care nu dorești să le expui AI-ului înainte de salvare.

### 2. Din export Termius CSV
- Dacă folosești Termius, poți exporta conexiunile în format CSV și le poți încărca direct în UI.

### 3. Din Termius Desktop (Offline & Automat pe Windows)
- Citește baza de date locală SQLite/IndexedDB din `%APPDATA%\Termius`.
- Extrage cheia de decriptare din **Windows Credential Manager**.
- Importă automat ierarhia completă: etichete, grupuri, utilizatori, parole și chei private SSH (inclusiv passphrase-ul).
- **Setup simplu**: dacă nu ai mediul Python pregătit, pe ecran există butonul **Instalează dependențele de import** (creează un venv local în `data/py` și instalează cititorul securizat `ccl_chromium_reader`).

---

## 7. Generarea și Gestionarea Tokenurilor MCP

Pentru ca un client AI să poată comunica cu `mcp-ssh`, acesta trebuie să dețină un token de acces:

1. Mergi în tab-ul **Tokenuri**.
2. În secțiunea de jos, introdu un nume descriptiv pentru client (ex. `claude-code`, `laptop-cursor`).
3. Apasă **Generează token**.
4. **Copiază tokenul generat**: Acesta este afișat **o singură dată**. În baza de date este salvat exclusiv hash-ul SHA-256 al acestuia.
5. **Revocare**: În cazul în care dorești să oprești accesul unui client, apasă pe **Revocă** lângă tokenul respectiv. Accesul este revocat instantaneu.

---

## 8. Conectarea Clienților AI

### Claude Code CLI
Rulează în terminalul tău:
```bash
claude mcp add --transport http ssh http://127.0.0.1:7778/mcp --header "Authorization: Bearer <TOKEN_GENERAT>"
```

### Claude Desktop
Deschide fișierul de configurare Claude Desktop (`%APPDATA%\Claude\claude_desktop_config.json` pe Windows):
```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://127.0.0.1:7778/mcp",
        "--header",
        "Authorization: Bearer <TOKEN_GENERAT>"
      ]
    }
  }
}
```

### Cursor / Windsurf
În setările MCP ale editorului, adaugă un server de tip `HTTP`:
- **URL**: `http://127.0.0.1:7778/mcp`
- **Headers**:
  - `Authorization`: `Bearer <TOKEN_GENERAT>`

---

## 9. Integrarea cu ChatGPT prin OpenAI Secure Tunnel

ChatGPT Web nu permite introducerea de chei Bearer personalizate. Pentru a rezolva această problemă în siguranță, fără a expune porturi publice pe router, `mcp-ssh` integrează clientul oficial **OpenAI `tunnel-client`**:

### Pasul 1: Obținerea credențialelor OpenAI Tunnel
1. Intră pe [platform.openai.com](https://platform.openai.com) > **Settings** > **Tunnels**.
2. Creează un tunel nou, asociază-l cu spațiul tău ChatGPT și copiază **Tunnel ID** (de forma `tunnel_...`).
3. Generează o cheie API OpenAI cu permisiunile `Tunnels: Read & Use`.

### Pasul 2: Configurarea în `mcp-ssh`
1. În Web UI ([http://127.0.0.1:7777](http://127.0.0.1:7777)), mergi în tab-ul **ChatGPT**.
2. Lipește **Tunnel ID** și **API Key**, apoi apasă **Salvează**.
3. Dacă nu ai executabilul descărcat, apasă pe **Descarcă client tunnel** (se descarcă binarul oficial OpenAI verificat prin SHA-256).
4. Apasă pe **Pornește tunel**. Starea va deveni verde (`running`, `ready`).
   - În fundal, se creează automat un token dedicat numit `chatgpt-tunnel`.

### Pasul 3: Activarea în ChatGPT Web
1. Mergi pe [chatgpt.com](https://chatgpt.com) > **Settings** > **Connected Apps / Plugins**.
2. Apasă pe **+ Add custom MCP server**.
3. La tipul conexiunii alege: **Tunnel**, apoi selectează tunelul configurat la Pasul 1.
4. La autentificare alege: **No authentication** (autentificarea o face automat `tunnel-client` pe mașina ta locală).
5. Salvează. ChatGPT va descoperi uneltele `list_hosts`, `run_command`, `read_file`, `get_host_info`, `list_clusters`, `kubectl`.

---

## 10. Fluxul de Aprobare Umană

Când un host sau cluster este setat pe modul **`approval`**:

1. AI-ul trimite o cerere de rulare a unei comenzi.
2. Comanda este interceptată și plasată în coada din tab-ul **Aprobări**.
3. Bara de navigație afișează numărul de cereri în așteptare (ex. `Aprobări (1)`).
4. Operatorul vede în UI:
   - Numele clientului AI (ex. `claude-desktop`, `chatgpt-tunnel`).
   - Hostul sau clusterul vizat.
   - Comanda exactă care urmează să fie rulată.
   - În cazul Kubernetes, conținutul complet al manifestului YAML trimis prin stdin.
5. Operatorul apasă:
   - **Aprobă**: comanda se execută imediat pe server, iar rezultatul este returnat AI-ului.
   - **Respinge**: comanda este anulată, iar AI-ul primește mesajul *"Command was denied by the operator"*.
6. Dacă operatorul nu răspunde în intervalul configurat (implicit 120 de secunde), comanda expiră automat (*timed out*).

---

## 11. Jurnalul de Audit

În tab-ul **Audit** poți vedea istoricul complet al activității:
- **Timp**: data și ora exactă la secundă.
- **Client**: numele tokenului cu care s-a autentificat AI-ul.
- **Host / Cluster**: ținta acțiunii.
- **Comandă**: comanda rulată.
- **Rezultat**: `ok`, `denied`, `blocked: read-only policy`, `timeout`, `error`.
- **Cod Ieșire & Latență**: codul de exit (ex. 0) și timpul de rulare în milisecunde.

Datele sunt persistate în fișierul `data/audit.jsonl`. Parolele sau cheile API sunt cenzurate automat din înregistrări.

---

## 12. Setări Globale

În tab-ul **Setări** poți configura parametrii de funcționare:
- **Auto-lock după (minute)**: timpul de inactivitate după care vault-ul se sigilează (0 = niciodată).
- **Limită output (bytes)**: cantitatea maximă de ieșire (stdout/stderr) returnată AI-ului (implicit 64 KB). Protejează fereastra de context a modelului împotriva comenzilor cu ieșire masivă (ex. dump-uri de fișiere).
- **Timeout aprobare (secunde)**: timpul maxim în care o cerere rămâne în așteptare în coada de aprobări (implicit 120 secunde).
- **Schimbă parola master**: solicită parola curentă și o re-encriptează pe cea nouă fără a pierde datele existente.

---

## 13. Depanare & FAQ

#### 1. AI-ul raportează eroarea `503 Service Unavailable`
- **Cauză**: Vault-ul este blocat (auto-lock).
- **Soluție**: Intră pe `http://127.0.0.1:7777` și introdu parola master pentru deblocare.

#### 2. Hostul dorit nu apare în lista returnată de `list_hosts`
- **Cauză**: HostMonitor a verificat conexiunea TCP și serverul este offline sau portul SSH este filtrat/blocat de un firewall.
- **Soluție**: Verifică dacă serverul este pornit și accesibil din rețeaua ta. Poți apăsa pe butonul **Verifică acum** din tab-ul Hosturi pentru o reinterogare forțată.

#### 3. Kubernetes: eroarea `kubeconfig references local files instead of embedding them`
- **Cauză**: Fișierul kubeconfig are căi relative sau absolute către certificate (`ca.crt`, `client.crt`) în loc să aibă datele inline.
- **Soluție**: Exportă un fișier complet cu:
  ```bash
  kubectl config view --raw --flatten > kubeconfig.yaml
  ```
  și încarcă acest fișier în UI.

#### 4. Cum revoc accesul dacă am suspiciuni asupra unui client?
- Mergi în tab-ul **Tokenuri** și apasă pe butonul **Revocă** din dreptul clientului.
- Dacă folosești ChatGPT, poți opri tunelul direct din tab-ul **ChatGPT** (apasă **Oprește**) sau revoca tokenul `chatgpt-tunnel`.
