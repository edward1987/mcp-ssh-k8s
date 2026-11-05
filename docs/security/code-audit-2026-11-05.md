# Audit de securitate — 2026-11-05

## Remediere — 2026-11-05

Cele patru constatări de mai jos au fost remediate în codul local:

- A1: blocare globală pentru cluster-info dump și opțiunile output-directory/profile/profile-output, inclusiv variantele cu underscore. Comenzile remote după delimitatorul exec `--` rămân tratate ca argumente remote.
- A2: bugete identity separate pe cont, invitație sau utilizator autentificat; headerele forwarded nu sunt folosite. MCP verifică tokenurile înaintea limitării răspunsurilor pentru credențiale invalide, astfel încât un buget epuizat de la același proxy nu respinge tokenurile valide. Protecția per cont poate limita în continuare autentificarea unui cont vizat; protecția contra volumelor mari de trafic rămâne responsabilitatea ingressului.
- A3: manifestele peste 20.000 caractere în modul approval sunt respinse înainte de crearea aprobării. Pentru manifestele acceptate, operatorul primește conținutul integral care va fi executat.
- A4: rezultatele includ complete și checks cu cod de ieșire și eroare. Erorile SSH, exit codes nenule, timeout, trunchiere și mesaje uzuale de lipsă a permisiunilor produc warning și raport incomplet, inclusiv în checklist. Eșecurile unei metode de verificare sunt păstrate conservator chiar dacă o metodă alternativă reușește. grep fără rezultate (exit 1, fără output) nu este tratat ca eroare.

Validare după remediere: 24 fișiere / 119 teste trecute și build TypeScript reușit. Testele noi acoperă filtrarea în toate modurile, manifestul ascuns după limita de aprobare, izolarea autentificării identity prin gateway, tokenuri MCP valide după epuizarea bugetului comun și rapoarte de securitate cu execuții eșuate/incomplete. Observația existentă ERR_ERL_CREATED_IN_REQUEST_HANDLER din testul de schimbare a originii OAuth rămâne deschisă; nu face parte dintre cele patru remedieri.

Constatările de mai jos descriu starea identificată înaintea remedierii.

Audit asupra stării locale din D:\apps\mcp-ssh, inclusiv modificările necomise. Nu au fost modificate sursele aplicației. Analiză statică a fluxurilor de autentificare, autorizare, vault, SSH, kubectl, sharing, gateway și administrare; inspecție orientată pe riscuri a importurilor, UI și deployment. Acesta nu este un pentest al infrastructurii și nu certifică absența altor vulnerabilități. Revizia nu a verificat exhaustiv fiecare ramură din fiecare fișier.

## Rezultate

### A1 — Ridicat: kubectl permite scrieri locale în modul read-only

Loc: src/k8s/kubectl.ts:93,101,133,149 și runKubectl.

Filtrul permite verbul cluster-info fără restricționarea subcomenzii dump și nu blochează output-directory, profile sau profile-output. Verificarea directă a funcției a returnat ok:true pentru ambele:

```
cluster-info dump --output-directory=/tmp/audit-proof
get pods --profile=cpu --profile-output=/tmp/audit-proof
```

Un client MCP autentificat cu acces la un cluster read-only poate astfel cere scrieri în directoare accesibile contului serviciului. Pentru dump, numele fișierelor sunt generate de kubectl; nu presupunem control arbitrar asupra conținutului sau RCE. Profiling introduce și o destinație de fișier aleasă de client. Impact: depășirea limitei dintre cluster și serverul aplicației, consum de disc și posibilă deteriorare a fișierelor accesibile. Un filesystem root read-only reduce impactul, dar volumele de date rămân inscriptibile.

Confirmat local: acceptarea de către filtru. Nu s-au executat comenzi pe clustere reale și nu s-au suprascris fișiere. Semantica dump este documentată oficial: https://kubernetes.io/docs/reference/kubectl/generated/kubectl_cluster-info/kubectl_cluster-info_dump/

Remediere: interzicerea globală a tuturor opțiunilor de acces local, inclusiv profiling; validare explicită pe verb/subcomandă și opțiuni acceptate; sandbox separat fără acces la datele aplicației pentru kubectl. Testele trebuie să acopere și modurile approval/free, deoarece aprobarea accesului la cluster nu acordă acces la discul serverului.

### A2 — Mediu: blocare globală a autentificării prin gateway

Loc: src/gateway.ts (proxy către 127.0.0.1), src/auth/web.ts:31, src/mcp/server.ts:207-209.

Gateway-ul elimină forwarded headers, iar backendurile folosesc req.ip pentru rate limiting. Cererile utilizatorilor prin gateway ajung de la aceeași adresă loopback. Un atacator fără cont poate consuma bugetul comun: 15 POST-uri către identity într-un minut sau 10 eșecuri Bearer către MCP. Cererile legitime ulterioare sunt respinse înainte de validarea credențialelor. POST-urile identity reușite consumă și ele bugetul comun. Impactul depinde de topologia proxy, dar gateway-ul inclus creează exact această condiție.

Confirmare: traseu static complet; nu s-a efectuat flood pe un serviciu live.

Remediere: limitare la ingress după IP-ul verificat și transmiterea unei identități de rețea numai printr-un canal proxy de încredere; limite suplimentare per cont/client. Nu activați trust proxy global pentru headere furnizate de client. Test cu două identități de rețea prin gateway.

### A3 — Ridicat: manifestul executat nu este integral vizibil la aprobare

Loc: src/service.ts:91-93 și apelul ulterior runKubectl; src/mcp/server.ts permite manifest de până la 500.000 caractere.

Interfața de aprobare primește doar primele 20.000 de caractere; procesul primește manifestul integral. Un client compromis poate pune un obiect benign urmat de padding, apoi un document YAML periculos după limita previzualizării. Operatorul vede marcajul de trunchiere, dar nu are conținutul ascuns disponibil în cererea de aprobare. Obiectele executate rămân limitate de RBAC-ul credențialelor Kubernetes; nu este un bypass RBAC și necesită aprobarea operatorului.

Remediere: respingerea manifestelor care nu pot fi examinate integral sau vizualizare completă/paginată, legată de hash-ul exact al conținutului executat. Test cu un al doilea document YAML după pragul de 20.000 caractere.

### A4 — Mediu: verificarea de securitate poate raporta OK când verificările eșuează

Loc: src/security.ts, funcția exec și calculul status de la linia 149.

Erorile SSH sunt convertite în text; status depinde doar de lista warnings. Nu toate verificările eșuate adaugă avertismente, iar codurile de ieșire nenule nu sunt tratate sistematic ca eșec. Un host fără permisiuni pentru loguri/utilitare sau cu conexiuni eșuate poate primi status ok și mesajul că verificările au trecut. Rezultatul este salvat și în checklist.

Remediere: rezultate structurate pe verificare cu success/error/unsupported, păstrarea exitCode și status general incomplete/error când lipsesc probele. Test cu toate comenzile eșuate și cu permission denied. Este o problemă de integritate a raportării, nu dovada că hostul este compromis.

## Validare și limite

- npm test -- --reporter=dot: 22 fișiere, 112 teste trecute.
- npm run build: reușit.
- npm audit --json: 0 vulnerabilități raportate, 266 dependențe în metadate; această verificare nu acoperă binarele externe sau defectele logicii aplicației.
- Testele emit ERR_ERL_CREATED_IN_REQUEST_HANDLER la reconstruirea routerului OAuth după schimbarea originii. De corectat prin construirea routerului în afara cererilor; nu este prezentat ca bypass confirmat.
- Runtime local observat: Node 24.22.1, sub minimul 24.22.2 declarat în package.json. Aliniați mediul de rulare; nu atribuim un CVE fără dovezi.
- Controale pozitive: OAuth cu PKCE și resource binding, MFA, sesiuni cu expirare, CSRF pe mutațiile protejate, separare personală a vaulturilor, revalidare după aprobare, respingerea kubeconfig exec/auth-provider și verificare TLS, pinning SSH după prima conexiune, containere non-root.
- Riscuri de proiectare: prima conexiune SSH folosește TOFU; shared-secret rămâne decriptabil prin cheia instanței și după revocarea share-ului, deoarece revocarea nu șterge snapshot-ul. Acestea merită documentate și întărite în funcție de modelul de amenințări.
- Nu au fost rulate testele browser, container sau Kubernetes, scanarea imaginii distribuite, verificarea ACL-urilor unei instalări reale, fuzzing ori teste de încărcare. Nu au fost utilizate credențiale de producție.

Prioritate: A1 și A3 înaintea expunerii către clienți MCP neîncrezători; apoi A2 și A4. Reaudit țintit după remediere, inclusiv teste de integrare într-un cluster izolat.
