# Conturi și OAuth

Modelul curent este descris în [PERSONAL_VAULTS.md](PERSONAL_VAULTS.md): vault personal per utilizator, partajări revocabile și HTTPS privat DNS-01. Instrucțiunile de mai jos despre un vault global și publicarea remote sunt pentru modelul anterior; nu publica aplicația pentru noul flux VPN.

Toate instalările, inclusiv cele locale, folosesc conturi individuale, parolă și TOTP. Un conector instalat în workspace nu acordă acces la vault. Administratorii gestionează toate resursele; membrii primesc numai granturile atribuite direct sau prin grupuri de securitate.

## Prima pornire și migrare

1. Oprește instanța veche și păstrează o copie a întregului director de date. Rulează o singură instanță a aplicației pentru acest director.
2. Pornește aplicația cu Node.js 24.22.2 sau ulterior în linia Node 24 LTS. Deschide `http://127.0.0.1:7777/identity/bootstrap` pe server.
3. Introdu parola master existentă sau alege una pentru vault nou. Creează primul administrator, setează o parolă de cont distinctă și adaugă cheia TOTP în autentificator.
4. Salvează codurile de recuperare afișate o singură dată. Autentifică-te și deschide interfața vaultului. Deblochează vaultul cu parola master.
5. Prima deblocare elimină tokenurile globale și dezactivează pornirea automată a tunelului vechi. Copia criptată `vault.json.pre-identity.bak` este creată înainte de migrare; nu este suprascrisă.
6. Refă configurațiile clienților din **Clienți AI** și selectează OAuth în ChatGPT. Elimină `MCP_SSH_TOKEN` și antetele Bearer statice din configurațiile vechi.

Vaultul rămâne blocat după restart. Autentificarea, MFA și discovery funcționează independent de deblocarea lui. Nu există ocolire prin autentificare cu parola master în endpointul MCP.

`http://127.0.0.1:7778/mcp` este adresa protocolului MCP. Interfața vaultului este pe `http://127.0.0.1:7777/`; accesarea rădăcinii portului MCP și linkul către vault din pagina OAuth ajung la interfața de administrare, inclusiv când porturile sunt personalizate. Pentru instalările HTTPS se folosește originea HTTPS configurată.

Un vault blocat sau încă necreat nu împiedică `initialize` și `tools/list` după OAuth valid. Catalogul conține numai definiții statice, fără datele resurselor. Orice apel de tool care citește resurse sau execută operații cere vault deblocat și păstrează verificările de proprietar, granturi și politici. Mesajul de eroare indică interfața de deblocare; ChatGPT nu primește parola master. După deblocare, conexiunea OAuth existentă poate continua fără o nouă autentificare.

Pentru ChatGPT pe un server local, menține Secure MCP Tunnel pornit și selectează **Connection: Tunnel** în configurația conectorului, nu o adresă loopback folosită ca endpoint public. Vezi [documentația oficială OpenAI pentru tunel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels). Readiness-ul tunelului, OAuth și discovery sunt etape separate. Auditul înregistrează acum rezultatele `mcp initialize` și `mcp tools/list`, fără tokenuri sau parametrii cererilor.

## Utilizatori și grupuri

Din **Conturi și acces**, administratorul generează invitații de unică folosință valabile 24 ore, distribuite manual. Activarea cere parolă de minimum 12 caractere și TOTP. Nu există înregistrare publică sau trimitere automată de email.

Administratorul atribuie ID-urile hosturilor și clusterelor unor utilizatori sau grupuri. ID-urile resurselor sunt disponibile prin API-urile administrative `/api/hosts` și `/api/clusters`, după login și deblocare. Etichetele organizatorice existente ale hosturilor nu sunt grupuri de securitate. Granturile se cumulează; un membru nou nu are acces. Modurile `read-only`, `approval`, `free` se aplică în continuare.

Resetarea unui cont generează o invitație nouă și invalidează autorizările și sesiunile vechi. Administratorul nu poate reseta sau dezactiva propriul cont din această interfață. Utilizarea unui cod de recuperare invalidează conexiunile și sesiunile anterioare. Păstrează codurile administratorului într-un loc separat; pierderea tuturor factorilor necesită recuperare operațională din backup, nu există resetare publică a administratorului.

## Publicare remote

Ambele listenere rămân pe loopback. Configurează un reverse proxy HTTPS cu certificat valid, care păstrează `Host` și `Authorization`, fără adăugarea unei credențiale globale:

```text
AUTH_URL=https://ssh.example.com
MCP_PUBLIC_URL=https://ssh.example.com/mcp
```

Proxy-ul public trimite `/identity/*`, `/authorize`, `/token`, `/register`, `/revoke`, `/.well-known/*` și `/mcp` către `127.0.0.1:7778`. Nu publica portul 7777 sau `/identity/bootstrap`. Administrarea vaultului rămâne locală; folosește acces administrativ la server pentru deblocare și aprobări. Antetele `X-Forwarded-*` nu sunt folosite ca sursă de identitate; aplicația nu activează implicit `trust proxy`.

Pentru Claude remote, endpointul MCP trebuie accesibil infrastructurii Anthropic. Pentru ChatGPT poți folosi endpoint HTTPS sau Secure MCP Tunnel cu OAuth. În cazul tunelului, setează `MCP_PUBLIC_URL` la URL-ul canonic al resursei expuse prin tunel și publică separat serviciul `AUTH_URL`; verifică metadata și audience pe traseul real înainte de distribuirea conectorului. Tunelul nu publică automat loginul și nu înlocuiește OAuth.

## Stocare și revocare

`data/identity/` conține SQLite și cheia de criptare a secretelor TOTP. Sunt protejate prin permisiuni POSIX sau ACL Windows pentru identitatea procesului, SYSTEM și administratori. Copiază împreună baza și cheia, cu aplicația oprită. Nu publica și nu include directorul în pachete. Schimbarea identității OS a serviciului poate necesita ajustarea ACL de către administrator.

Bridge-ul stdio păstrează credențialele în `~/.mcp-ssh/oauth`, în afara workspace-ului. URL-ul de login este afișat pe stderr. Fiecare utilizator OS folosește propriile credențiale. Nu rula două bridge-uri simultan pentru același endpoint și profil în timpul reconectării OAuth.

Tokenurile de acces expiră după 10 minute. Refresh tokenurile au maximum 30 zile, cu rotație și detectarea reutilizării. Sesiunile browserului expiră după 30 minute de inactivitate sau 8 ore. Din pagina contului poți revoca toate conexiunile și sesiunile. Eliminarea granturilor și dezactivarea contului blochează imediat execuțiile noi și cele încă în așteptarea aprobării; nu anulează comenzi deja trimise hosturilor.

## CSP si pagina de consent

Chrome/Edge verifica `form-action` si pentru redirectul de dupa formularul de consent. Pagina unei cereri OAuth active permite, pe langa `'self'`, numai originea callback-ului acelei cereri, validat in fluxul OAuth. Nu se permit wildcard-uri, toate porturile locale sau toate callback-urile inregistrate ale clientului. Exceptia nu se aplica paginilor de login/administrare, cererilor expirate sau utilizatorilor neautentificati; CSRF, Origin si PKCE raman verificate.

Dupa actualizarea aplicatiei, reporneste procesul si reia conectarea din clientul AI. O cerere anterioara poate fi deja consumata de POST, chiar daca browserul a blocat ulterior redirectul. Nu reutiliza pagina veche de consent. Blocarea cererii Chrome DevTools `/.well-known/appspecific/com.chrome.devtools.json` prin CSP este separata de autorizarea OAuth si nu necesita largirea `connect-src`.

Vezi [comportamentul CSP pentru redirecturi de formular](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action).

## Referințe

- [OpenAI: autentificare MCP](https://developers.openai.com/plugins/build/auth)
- [OpenAI: Secure MCP Tunnel și OAuth](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [Claude: conectori remote și autentificare individuală](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
- [Claude Code: MCP și OAuth](https://code.claude.com/docs/en/mcp)
