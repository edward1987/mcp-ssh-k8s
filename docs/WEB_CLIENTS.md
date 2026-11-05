# Gemini si Claude

In **Administrare instanta** (`/identity/admin`) exista sectiunea **Gemini Web si Claude Web**, disponibila administratorilor chiar cu vaulturile personale blocate.

## Configurare automata Cloudflare

In admin foloseste sectiunea **Configurare automata Cloudflare**:

1. Apasa **Creeaza API token Cloudflare**. Linkul deschide formularul oficial cu permisiunile Account → Cloudflare Tunnel → Edit, Zone → DNS → Edit si Zone → Zone → Read. Verifica cele trei permisiuni si restrange accesul la contul si domeniile necesare, apoi confirma crearea tokenului in Cloudflare. Domeniul trebuie sa fie deja activ in Cloudflare.
2. Copiaza API tokenul in admin si apasa **Conecteaza contul si incarca domeniile**. Alternativ, poti selecta **Global API Key** si introduce cheia impreuna cu emailul contului. Tokenul API cu permisiuni restranse este optiunea recomandata. Campul gol pastreaza credentialul salvat pentru acelasi tip de autentificare si acelasi email.
3. Alege domeniul din lista incarcata automat, introdu un subdomeniu simplu, de exemplu `mcp`, si alege daca doresti conectare automata la pornirea instantei.
4. Apasa **Creeaza si conecteaza — 1 click**. Aplicatia instaleaza cloudflared daca lipseste, creeaza un tunel administrat de Cloudflare, configureaza ruta spre portul MCP local cu Host header corect si fallback 404, creeaza CNAME-ul proxied si obtine tokenul de rulare. URL-ul OAuth si discovery-ul MCP sunt activate imediat, fara restart, iar conexiunea este pornita.
5. Actualizeaza starea din admin. Endpointul rezultat este `https://mcp.domeniul-tau/mcp`; adauga-l in Gemini sau Claude si autorizeaza contul propriu. Propagarea DNS si emiterea certificatului edge Cloudflare pot dura dupa finalizarea configurarii.

Daca `AUTH_URL` sau `MCP_PUBLIC_URL` sunt fixate in mediul procesului, trebuie sa corespunda hostname-ului ales. O nepotrivire opreste configurarea inainte de crearea resurselor; corecteaza mediul si reporneste aplicatia. Schimbarea originii OAuth necesita reautorizarea conectorilor existenti.

Credentialul API si tokenul de rulare sunt stocate separat, criptat. Erorile API nu expun credentialele sau raspunsurile brute. Inregistrarile DNS incompatibile nu sunt suprascrise. Etapele si ID-urile resurselor sunt persistente: la un esec apasa **Reia configurarea si conecteaza — 1 click** cu acelasi domeniu si subdomeniu. Tunelul si CNAME-ul deja create sunt refolosite. Inclusiv un raspuns pierdut la crearea tunelului poate fi recuperat folosind numele unic rezervat instantei. Schimbarea zonei sau a hostname-ului unei configuratii administrate existente se face explicit in Cloudflare; wizardul nu sterge resursele vechi.

Linkul de creare a tokenului precompleteaza formularul, iar confirmarea crearii ramane in contul Cloudflare, conform [documentatiei pentru template URLs](https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/). Automatizarea foloseste [API-ul oficial pentru creare tunel, ingress si DNS](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel-api/).

## Configurare manuala cu un tunel existent

1. Creeaza un tunel Cloudflared administrat din Cloudflare Zero Trust. Foloseste un hostname stabil din domeniul tau, de exemplu `mcp.example.com`.
2. Configureaza public hostname pentru service `HTTP`, URL `127.0.0.1:7778` (sau portul MCP ales). Cloudflared este instalat in mediul aplicatiei; intr-un container sau pod, loopback indica acelasi container/pod. Pastreaza hostname-ul HTTP public sau seteaza HTTP Host Header la hostname-ul public configurat. Nu directiona ruta spre portul admin `7777`.
3. In admin apasa **Instaleaza cloudflared**. Sunt acceptate Windows x64 si Linux x64/ARM64, in functie de existenta binarului oficial cu digest SHA-256. Instalarea se face in directorul persistent de date, fara privilegii de sistem. Pentru actualizare opreste mai intai tunelul.
4. Salveaza URL-ul public HTTPS si tokenul tunelului. Tokenul nu este un API token DNS Cloudflare; foloseste tokenul connectorului din configuratia tunelului. Este criptat pe disc si transmis runtime-ului prin mediu, fara afisare in argumentele procesului sau in pagina admin. Un camp gol pastreaza tokenul existent.
5. Bifeaza **Conecteaza automat la pornirea instantei** daca doresti pornire automata. Salveaza si reporneste aplicatia pentru activarea noii origini OAuth. Daca sunt definite `AUTH_URL` si `MCP_PUBLIC_URL`, seteaza-le la `https://mcp.example.com` si `https://mcp.example.com/mcp`; variabilele de mediu au prioritate.
6. Apasa **Conecteaza Gemini / Claude Web** daca nu ai ales pornirea automata. **Deconecteaza** opreste transportul pana la urmatoarea conectare manuala sau pornire a aplicatiei. Debifeaza si salveaza pentru a dezactiva si pornirea la urmatorul restart. Oprirea neasteptata a procesului determina o noua incercare dupa cinci secunde; Cloudflared gestioneaza reconectarea proprie la retea.

Cele doua aplicatii folosesc acelasi transport, deci oprirea lui intrerupe accesul ambelor prin aceasta ruta. Starea **Conectat la Cloudflare** indica inregistrarea transportului; nu certifica autentificarea conturilor sau configurarea DNS/rutei. Nu pune un login interactiv Cloudflare Access in fata rutei MCP/OAuth. Aceasta ruta publica accesul HTTPS la MCP si paginile sale de autentificare; politicile OAuth, MFA si permisiunile individuale continua sa se aplice. Administrarea si deblocarea vaultului se fac in interfata aplicatiei, separat de autentificarea conectorului.

## Gemini Web

Adauga `https://mcp.example.com/mcp` in setarile pentru aplicatii personalizate ale Gemini si autorizeaza contul propriu al acestei aplicatii. Daca optiunea nu este disponibila contului tau, foloseste [Gemini Apps Developer Mode](https://gemini.google.com/devmode): **Create new**, apoi **MCP Server URL**, conform [instructiunilor Google](https://developers.google.com/connected-apps/mcp/dev-mode/usage). Disponibilitatea interfetei depinde de cont si de rollout-ul Google. Transportul instalat aici este Cloudflare; nu se presupune existenta unui runtime oficial de tunel Gemini.

## Claude Web

In Claude: **Settings → Connectors → Add custom connector**, introdu `https://mcp.example.com/mcp`, apoi autorizeaza accesul prin OAuth. Vezi [documentatia Anthropic](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).

[Claude Remote Control](https://code.claude.com/docs/en/remote-control) conecteaza o sesiune Claude Code locala la interfata web/mobile prin conexiuni outbound. Este o functie diferita de conectarea unui server MCP la chatul Claude; nu este necesara pentru acest flux.

## Gemini CLI si Claude Code

Configuratiile OAuth pentru Gemini CLI, Claude Code, Claude Desktop si Codex sunt disponibile in **Clienti AI**, precum si in admin pentru clientii Gemini/Claude. Clientii CLI ruleaza pe masina utilizatorului si nu necesita instalarea lor pe serverul MCP. Gemini CLI foloseste `mcpServers.ssh.httpUrl` in `~/.gemini/settings.json`, apoi `/mcp auth ssh`. Claude Code foloseste `claude mcp add --scope user --transport http ssh URL`, apoi `claude mcp login ssh`. Fiecare utilizator autorizeaza accesul cu identitatea sa; instalarea transportului nu acorda acces implicit la vaulturi.
