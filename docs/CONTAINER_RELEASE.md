# Release Docker și Kubernetes

Aceeași imagine Linux amd64 rulează în Docker Compose și Kubernetes. Manifestul aplicației este semnat Ed25519 la buildul final. Distribuția folosește un digest OCI, nu `latest`. Deploymentele păstrează aceeași cheie publică de încredere și aceeași politică de oprire la incident ca distribuția Windows.

## Configurarea CI

1. Configurează mediul GitHub `release` cu aprobări și restricții pentru branch/tag. YAML-ul nu activează singur aceste protecții.
2. Salvează cheia privată Ed25519 PEM în secretul mediului `MCP_SSH_INTEGRITY_SIGNING_KEY`. Nu o pune în Git, în build args sau în configurația containerului.
3. Permite workflow-ului publicarea în GHCR și generarea atestărilor. Workflow-ul `release-container.yml` rulează la tag `v<package.version>` sau manual de pe branch-ul implicit; rularea manuală publică un tag `candidate-<commit>`.
4. PR-urile și testele obișnuite folosesc chei efemere independente. Aceste imagini sunt numai pentru test și nu sunt acceptate de generatorul bundle-ului de release.

Cheia privată este accesibilă doar procesului BuildKit de semnare prin [secret mounts](https://docs.docker.com/build/building/secrets/). Cheia publică nu este secretă; este fixată în imagine și în deployment. Directorul aplicației este read-only pentru UID 1000. Datele și markerul de incident se află pe volumul persistent, în afara imaginii.

## Pașii de publicare

Workflow-ul compilează și testează aplicația pe Linux, construiește imaginea semnată, rulează testele Docker și un cluster kind temporar, apoi scanează imaginea. Orice CVE HIGH/CRITICAL, inclusiv fără fix disponibil, blochează publicarea. Nu există excluderi CVE pentru livrare.

Imaginea verificată este publicată direct prin `docker push`, fără un al doilea build între test și publicare. Workflow-ul adaugă o atestare GitHub de proveniență legată de digest, produce un SBOM SPDX și atașează artifactul `signed-container-release`. Acesta conține metadata buildului și un folder `deployment/` cu:

- `compose.yaml` și `kubernetes.yaml`, cu digestul exact și cheia publică fixată;
- `integrity.pub`, cheia publică SPKI DER în base64;
- `release.json`, cu versiunea, platforma, commitul și referința imaginii.

Pipeline-ul este pregătit în cod; publicarea reală și protecțiile mediului necesită configurarea contului GitHub. Nu au fost publicate imagini în timpul implementării locale. Cheile efemere folosite la teste nu devin chei reale de release.

## Verificare și instalare

Verifică atestarea imaginii față de repository-ul de încredere, verifică workflow-ul/commitul din rezultat și păstrează digestul exact. [GitHub documentează verificarea atestărilor](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/verifying-the-provenance-of-an-artifact):

```sh
gh attestation verify oci://ghcr.io/OWNER/REPOSITORY@sha256:DIGEST --repo OWNER/REPOSITORY
```

Adaptează domeniul HTTPS, secretul TLS, ingress controllerul și destinațiile NetworkPolicy înainte de pornire. Bundle-ul folosește inițial `mcp.example.com`; CIDR-urile de documentație blochează destinațiile reale până la configurare. Poți regenera bundle-ul fără cheia privată folosind metadata publică verificată:

```sh
node scripts/render-deployment.mjs --image ghcr.io/OWNER/REPOSITORY@sha256:DIGEST --build-metadata build.json --origin https://ssh.example.org --output deployment
docker compose -f deployment/compose.yaml up -d
# Sau, după pregătirea TLS și revizuirea regulilor de rețea:
kubectl apply -f deployment/kubernetes.yaml
```

Pentru registry privat, configurează separat autentificarea Docker sau `imagePullSecrets` în namespace. Pachetul nu include credențiale de registry, certificate private, vaulturi sau cheia privată de semnare.

Kubernetes folosește o singură replică, `Recreate`, PVC, profil seccomp RuntimeDefault, fără token de ServiceAccount, fără capabilities, fără escaladare și cu filesystem read-only. Nu monta Docker socket sau kubeconfigul administratorului gazdei. Detaliile TLS, backup, bootstrap și recuperare sunt în [DEPLOYMENT.md](DEPLOYMENT.md) și [INTEGRITY.md](INTEGRITY.md).

## Verificare locală izolată

```sh
node scripts/build-container.mjs --tag mcp-ssh-k8s:local --test-key --output release/container/test-build.json
npm run test:container
# Necesită kind; folosește exclusiv un cluster temporar:
npm run test:k8s
```

`--test-key` generează cheia numai în memoria procesului și o transmite ca secret de build. Nu publică imaginea. O imagine de dezvoltare nesemnată necesită explicit `docker build --target runtime-dev`; distribuția implicită nu acceptă lipsa cheii/semnăturii. Platforma de release testată este Linux amd64; suportul arm64 necesită validare separată înainte de publicare.
