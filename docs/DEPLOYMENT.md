# Docker, Kubernetes si Linux

Aplicatia ruleaza ca **o singura instanta**, cu date persistente si vaulturile blocate dupa restart. SQLite, vaulturile deblocate, limitarile de autentificare si aprobarile sunt locale procesului. Nu folosi replici multiple, HPA sau un volum partajat intre instante. Strategia Kubernetes este `Recreate`; actualizarile implica o scurta intrerupere.

Porturile interne `7777` (administrare) si `7778` (MCP/OAuth) asculta exclusiv pe loopback. Gateway-ul optional `8080` distribuie cererile catre ele. Pentru servere, `AUTH_URL=https://domeniu` si `MCP_PUBLIC_URL=https://domeniu/mcp` trebuie sa aiba aceeasi origine. Gateway-ul este un backend HTTP: TLS se termina in reverse proxy/ingress. Nu publica backend-ul direct pe internet. Nu monta socket-ul Docker, directorul home al gazdei sau credentiale Kubernetes de administrator in container.

## Docker Compose

Docker si Kubernetes folosesc aceeasi imagine OCI semnata. Workflow-ul `release-container.yml` construieste si testeaza Linux amd64, scaneaza CVE-urile, publica imaginea testata in GHCR si genereaza un bundle cu digestul exact si cheia publica. Configurati mai intai secretul de semnare si protectiile mediului `release`, conform [ghidului de release](CONTAINER_RELEASE.md). Nu a fost publicata automat o imagine prin aceasta modificare.

1. Alege domeniul HTTPS si configureaza DNS catre serverul/proxy-ul privat. Instaleaza certificatul TLS in proxy. Un exemplu nginx se afla in `deploy/nginx.conf`; configureaza domeniul si caile certificatului.
2. Creeaza `.env` local (este ignorat de Git):

```dotenv
AUTH_URL=https://mcp.example.com
MCP_PUBLIC_URL=https://mcp.example.com/mcp
MCP_SSH_IMAGE=ghcr.io/OWNER/REPOSITORY@sha256:DIGEST_DIN_RELEASE
MCP_SSH_INTEGRITY_PUBLIC_KEY=CHEIA_PUBLICA_BASE64_DIN_RELEASE
```

3. Verifica provenienta digestului si cheia publica din release, apoi porneste imaginea distribuita:

```sh
docker compose pull
docker compose up -d
docker compose ps
docker compose exec app node scripts/healthcheck.mjs
docker compose exec app node scripts/bootstrap.mjs
```

Ultima comanda necesita terminal interactiv. Cere numele administratorului si parola master fara a o afisa sau a o include in argumentele procesului. Deschide invitatia unica afisata, seteaza parola de cont, activeaza TOTP si salveaza codurile de recuperare. Invitatia este un secret: nu o distribui si nu o copia in loguri.

Pentru date noi, creeaza ulterior vaultul personal din interfata; parola vaultului personal este separata de parola contului. Pentru o instalare veche, foloseste la bootstrap parola master existenta, apoi fluxul explicit de migrare din interfata. Nu monta acelasi volum cat timp instanta veche ruleaza.

Compose publica `8080` doar pe `127.0.0.1`. Un proxy instalat direct pe gazda foloseste `http://127.0.0.1:8080`. Pentru un proxy containerizat foloseste o retea Docker privata comuna si upstream `app:8080`, fara publicarea portului aplicatiei pe toate interfetele.

Containerul ruleaza ca `1000:1000`, fara capabilities si fara escaladarea privilegiilor, cu filesystem read-only, memorie/PID limitate, `/tmp` in tmpfs si volum numit pentru `/var/lib/mcp-ssh`. Imaginea de productie nu contine shell sau npm. Foloseste `docker compose exec app node ...` pentru operatiuni, nu `sh`. `unzip` este inclus doar pentru instalarea componentului Linux de tunnel; instalarea acestuia necesita acces de iesire la furnizor.

Imaginea include `kubectl v1.37.2`, din buildul Chainguard cu dependente corectate, fixat prin digest SHA256. Selecteaza un build verificat compatibil cu clusterele administrate (in general diferenta de cel mult o versiune minora). Pentru alta versiune, parametrul `KUBECTL_IMAGE` trebuie sa indice o imagine de incredere fixata prin digest, cu binarul la `/usr/bin/kubectl`:

```sh
node scripts/build-container.mjs --tag mcp-ssh-k8s:local --output release/container/build.json
```

Comanda necesita cheia privata de semnare in mediul de build; cheia nu se transmite containerului rulat. Pentru teste izolate foloseste `--test-key`; aceasta imagine nu se publica. Targetul Docker implicit refuza lipsa semnaturii. Doar `docker build --target runtime-dev` permite explicit o imagine nesemnata de dezvoltare. Revizuieste rezultatul scanarii pentru versiunea aleasa. Actualizeaza digesturile imaginilor de baza si versiunile explicit, reconstruieste si rescaneaza; un tag local existent nu se actualizeaza singur. [Imaginea kubectl Chainguard](https://images.chainguard.dev/directory/image/kubectl/overview) este o dependenta externa, iar disponibilitatea versiunilor trebuie verificata la actualizare.

## Kubernetes

Exemplele din `deploy/k8s` presupun un controller Traefik existent, entrypoint TLS `websecure`, un CNI cu NetworkPolicy si o clasa implicita de storage care suporta `fsGroup`. Ajusteaza ingressClass, namespace-ul/labelurile controllerului si regulile DNS pentru infrastructura ta. Controllerul nu este instalat de aceste manifeste.

Inainte de aplicare:

- Inlocuieste `mcp.example.com` in ingress si variabilele deploymentului.
- Foloseste `kubernetes.yaml` din bundle-ul de release sau inlocuieste imaginea placeholder cu digestul verificat si `deploy/k8s/integrity-public-key.txt` cu cheia publica din release. Deploymentul cere semnatura; un tag mutabil sau o cheie dintr-o sursa neverificata nu este o configuratie de productie.
- Inlocuieste CIDR-urile de documentatie din NetworkPolicy cu destinatiile SSH/API aprobate si porturile lor. Configuratia initiala blocheaza destinatiile reale. Adauga explicit iesirile necesare pentru tunnel/Cloudflare/ACME daca le folosesti; NetworkPolicy standard nu filtreaza dupa FQDN.
- Pregateste certificatul TLS in namespace-ul dedicat. Daca folosesti cert-manager, configureaza emiterea separat. Configureaza limita de corp la 5 MiB, rate limiting pentru autentificare, timeout >=650s si streaming fara buffering in controller. TLS-ul intern Cloudflare din aplicatie este optional; foloseste terminarea TLS la ingress pentru acest deployment.

```sh
kubectl apply -f deploy/k8s/namespace.yaml
kubectl -n mcp-ssh create secret tls mcp-ssh-tls --cert=fullchain.pem --key=privkey.pem
kubectl apply -k deploy/k8s
kubectl -n mcp-ssh rollout status deployment/mcp-ssh
kubectl -n mcp-ssh exec -it deployment/mcp-ssh -- node scripts/bootstrap.mjs
```

Nu exista RBAC asupra clusterului gazda si nu se monteaza token de ServiceAccount. Accesul la clusterele tinta foloseste exclusiv kubeconfigurile introduse in vault. Fisierele trebuie sa includa certificatele/cheile/tokenurile; `exec`, `auth-provider`, fisierele externe, proxy-uri si dezactivarea verificarii TLS sunt respinse. Roteste credentialele cu durata scurta; EKS/GKE/AKS cu executabile de autentificare necesita un flux separat de emitere a credentialelor, in afara procesului aplicatiei.

Pentru comenzile MCP kubectl, scrie flagurile scurte separat (de exemplu `-A -w`, nu `-Aw`; watch ramane interzis in read-only). Sunt acceptate valori atasate pentru flaguri de tip valoare, precum `-nproduction`, `-owide` sau `-lapp=web`. Gruparea flagurilor este respinsa pentru a impiedica ascunderea override-urilor de server/fisiere printre optiuni booleene.

`/healthz` indica faptul ca procesul raspunde. `/readyz` verifica si listener-ele interne si devine indisponibil la oprire. Un vault blocat nu face probele sa esueze si nu declanseaza restarturi in bucla. Aceste endpointuri nu expun conturi, IP-uri tinta sau starea vaulturilor.

## Linux fara Docker

Instaleaza Node 24 LTS actualizat, npm si, optional, un kubectl verificat compatibil cu clusterele tinta. Construieste ca utilizator obisnuit, pe Linux (nu copia `node_modules` de pe Windows):

```sh
npm ci --ignore-scripts
npm run build
npm test
npm prune --omit=dev --ignore-scripts
# In mediul de build de incredere, cu cheia de semnare configurata:
node scripts/integrity.mjs create . --signed
sudo useradd --system --home-dir /var/lib/mcp-ssh --shell /usr/sbin/nologin mcp-ssh
sudo install -d -m 0755 /opt/mcp-ssh /etc/mcp-ssh
sudo cp -R dist web scripts node_modules package.json package-lock.json integrity.json integrity.sig integrity.pub /opt/mcp-ssh/
sudo chown -R root:root /opt/mcp-ssh
sudo chmod -R go-w /opt/mcp-ssh
sudo install -m 0644 deploy/linux/mcp-ssh.service /etc/systemd/system/mcp-ssh.service
sudo install -m 0600 deploy/linux/environment.example /etc/mcp-ssh/environment
```

Adapteaza `/etc/mcp-ssh/environment` la domeniu/proxy si fixeaza cheia publica prin `MCP_SSH_INTEGRITY_PUBLIC_KEY`, cu `MCP_SSH_REQUIRE_SIGNED_INTEGRITY=1`. Cheia privata nu se copiaza pe server si nu ramane in mediul serviciului. Unitatea asteapta Node la `/usr/bin/node`; modifica `ExecStart` daca distributia il instaleaza in alta locatie. Kubectl trebuie sa fie in PATH-ul serviciului sau configurat prin `KUBECTL_PATH`. Nu folosi un Node instalat in home, deoarece `ProtectHome=true` blocheaza acel director.

```sh
sudo systemd-analyze verify /etc/systemd/system/mcp-ssh.service
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-ssh
sudo systemctl status mcp-ssh
sudo journalctl -u mcp-ssh -n 50
sudo -u mcp-ssh env AUTH_URL=https://mcp.example.com node /opt/mcp-ssh/scripts/bootstrap.mjs
```

Serviciul foloseste directoarele gestionate de systemd `/var/lib/mcp-ssh` si `/run/mcp-ssh`, umask `0077`, fara capabilities, cu acces la filesystem limitat si fara acces la home. Nu cere root pentru runtime. TLS-ul pe `443` este gestionat de reverse proxy; nu adauga `CAP_NET_BIND_SERVICE` aplicatiei.

## Backup, restore si actualizare

Opreste instanta inainte de backup si copiaza **intregul** director de date: identity SQLite + cheia `identity.key`, vaulturi + fisierele envelope, legacy vault, audit si configurarea runtime. Un backup doar al `vault.json` nu restaureaza identitatile si vaulturile personale. Protejeaza si cripteaza backupul; cheia identity se afla alaturi de baza de date si protejarea discului/backupului este esentiala. Nu include datele in imaginea Docker.

Restaureaza offline, verifica ownership/permisii pentru UID 1000 in container sau utilizatorul systemd, apoi porneste o singura instanta. Nu sterge volumul/PVC la upgrade (`docker compose down -v` sterge datele). Testeaza restaurarea separat; dupa restart, fiecare utilizator deblocheaza din nou vaultul personal. SIGTERM inchide listener-ele, refuza aprobarile ramase si blocheaza vaulturile, cu maximum 10s pentru inchidere.

Pentru istoricul de audit obligatoriu sau detectarea modificarilor de catre un administrator al gazdei, trimite jurnalul catre un colector extern protejat. `audit.jsonl` este un fisier local, nu un registru imuabil.

## Verificari inainte de livrare

```sh
npm audit --audit-level=moderate
npm run build
npm test
npm run test:browser
docker build --target test .
node scripts/build-container.mjs --tag mcp-ssh-k8s:local --test-key
npm run test:container
# Necesita kind si Docker; creeaza/sterge exclusiv un cluster temporar:
npm run test:k8s
```

Workflow-ul `.github/workflows/security.yml` ruleaza testele pe Windows/Linux, verificarile de container si scanari pentru CVE-uri, secrete si configuratii. Scanarea HIGH/CRITICAL blocheaza livrarea inclusiv cand vulnerabilitatea este in kubectl sau in baza imaginii; consultarile temporare nu sunt aprobari de productie. Vezi `SECURITY_REVIEW.md` pentru rezultatele si limitarile verificarii curente.

La modificarea detectata a codului, procesul iese cu 78 si persista incidentul in volumul de date/PVC. Compose limiteaza restarturile la 3 incercari; Kubernetes poate intra in CrashLoopBackOff, dar nu deblocheaza aplicatia. Nu eliminati volumul/PVC pentru a rezolva incidentul. Opriti/scalati la zero, investigati, reinstalati imaginea verificata si arhivati/eliminati manual numai markerul incidentului, conform [INTEGRITY.md](INTEGRITY.md). La restart normal, vaulturile raman blocate; limita implicita de inactivitate este 10 minute pentru vaulturile noi, configurabila per vault.

Referinte: [Kubernetes security checklist](https://kubernetes.io/docs/concepts/security/application-security-checklist/), [Traefik Ingress](https://doc.traefik.io/traefik/reference/routing-configuration/kubernetes/ingress/), [retragerea ingress-nginx](https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/). Exemplele nu folosesc controllerul ingress-nginx retras.
