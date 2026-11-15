# Wolin (月印千江) Home Server Self-Hosting Guide

**[English](#1-english-guide)** • **[한국어](#2-한국어-가이드)**

---

## 1. English Guide

Wolin (`wolin-server`) compiles into a single **~23 MiB** native Rust binary combining **W3C Solid 0.11 LDP**, **Solid-OIDC + RFC 9449 DPoP**, **Oxigraph RDF/SPARQL 1.1**, **Apache OpenDAL**, **W3C WAC/ACP Policy Enforcement**, and **Native MCP (`/mcp`, `/mcp/sse`)**.

With an idle memory footprint of **~21 MiB RSS**, Wolin runs effortlessly on Raspberry Pi 4/5 (`arm64`), Intel N100 mini-PCs, NAS appliances (Synology/QNAP/TrueNAS), and Linux home servers.

### 1.1 Configuration & Precedence

Wolin enforces strict 3-tier configuration precedence:

```text
CLI flag  >  WOLIN_* environment variable  >  built-in default
```

| Environment Variable | CLI Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `WOLIN_LISTEN_ADDR` | `--listen-addr <IP:PORT>` | `127.0.0.1:4000` | Bind socket address (`IP:PORT` literal; container default `0.0.0.0:4000`) |
| `WOLIN_HOST` | `--host <IP>` | `127.0.0.1` | Bind IP literal (`127.0.0.1`, `0.0.0.0`, `::1`, `::`) |
| `WOLIN_PORT` | `-p`, `--port <PORT>` | `4000` | Bind TCP port |
| `WOLIN_STORAGE_DIR` | `-d`, `--storage-dir <DIR>` / `--in-memory` | *(in-memory)* | Persistent root directory (`blobs/` + `graph/`, `0700`); set `memory` for ephemeral |
| `WOLIN_BASE_URL` | `--base-url <URL>` | `http://<host>:<port>` | Public canonical origin for RDF IRIs, `Location`, and discovery |
| `WOLIN_POD_PREFIX` | `--pod-prefix <URI>` | `wolin://pod` | Internal `ResourceUri` prefix evaluated by the WAC/ACP PDP |
| `WOLIN_POD_CLOUD_DOMAIN` | `--pod-cloud-domain <DOM>` | `wolin.cloud` | Root domain for `{pod_id}.{domain}` multi-tenant `Host` routing |
| `WOLIN_OIDC_ISSUER` | `--oidc-issuer <URL>` | `https://auth.wolin.id` | Trusted Solid-OIDC / ZITADEL JWT issuer URL |
| `WOLIN_OIDC_AUDIENCE` | `--oidc-audience <AUD>` | *(none)* | Optional required OIDC JWT `aud` claim |
| `WOLIN_OWNER_WEBID` | `--owner-webid <URI>` | *(none)* | Bootstrap WebID or DID (`did:key:...`, `did:web:...`) with root WAC owner rights |
| `WOLIN_REQUIRE_EXPLICIT_DELEGATION` | `--require-explicit-delegation` | `false` | Require explicit `DelegationGrant` for delegated AI agents (`act.sub`) |
| `WOLIN_MCP_ENABLED` | `--mcp-enabled <BOOL>` / `--no-mcp` | `true` | Enable or disable Native MCP JSON-RPC (`/mcp`) and SSE (`/mcp/sse`) |
| `WOLIN_MAX_BODY_BYTES` | `--max-body-bytes <BYTES>` | `16777216` | Maximum accepted HTTP payload size in bytes (16 MiB) |
| `WOLIN_MAX_OPEN_PODS` | `--max-open-pods <COUNT>` | `256` | Max open per-Pod RocksDB stores in the bounded LRU cache |
| `WOLIN_DEFAULT_POD_QUOTA_BYTES` | `--pod-quota-bytes <BYTES>` | `1073741824` | Default per-Pod storage quota in bytes (`1 GiB`) |
| `WOLIN_LOG` / `RUST_LOG` | *(env only)* | `info,...` | Structured `tracing` log filter |

### 1.2 Quickstart A: Docker Compose (Recommended)

```bash
git clone https://github.com/wolin-id/wolin.git
cd wolin
cp .env.example .env

# Build and start Wolin in the background (binds 127.0.0.1:4000 by default)
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build

# Verify container health and discovery metadata
curl -fsS http://127.0.0.1:4000/healthz
curl -fsS http://127.0.0.1:4000/.well-known/wolin
```

- **LAN exposure**: To access Wolin directly from other devices on your home LAN without a reverse proxy, set `WOLIN_HTTP_BIND=0.0.0.0:4000` and `WOLIN_BASE_URL=http://<LAN_IP>:4000` in `.env`.
- **Disable MCP**: Set `WOLIN_MCP_ENABLED=false` in `.env` if you want pure Solid 0.11 LDP without exposing `/mcp` and `/mcp/sse`.

### 1.3 Quickstart B: Custom Domain + Automatic HTTPS with Caddy

If your home router forwards TCP `80` and `443` (and UDP `443` for HTTP/3) to your server:

1. Point an `A` / `AAAA` DNS record (e.g. `pod.example.org`) to your home public IP.
2. Prepare `.env` (and optionally copy `deploy/Caddyfile.example` to `deploy/Caddyfile` with `WOLIN_CADDYFILE=./Caddyfile` if customizing):
   ```bash
   cp .env.example .env
   ```
3. Edit `.env`:
   ```dotenv
   WOLIN_BASE_URL=https://pod.example.org
   WOLIN_POD_CLOUD_DOMAIN=example.org
   WOLIN_PUBLIC_HOST=pod.example.org
   ACME_EMAIL=you@example.org
   ```
4. Launch Wolin + Caddy with the `caddy` profile:
   ```bash
   docker compose --env-file .env -f deploy/docker-compose.yml --profile caddy up -d --build
   ```

Caddy automatically obtains and renews Let's Encrypt / ZeroSSL certificates, forwards `Host` and `X-Forwarded-Proto: https`, and disables response buffering (`flush_interval -1`) on `/mcp/sse`.

### 1.4 Quickstart C: Cloudflare Tunnel (No Port Forwarding / CGNAT)

Ideal for home networks behind ISP CGNAT or apartment routers where ports `80`/`443` cannot be opened:

1. In **Cloudflare Zero Trust → Networks → Tunnels**, create a `cloudflared` tunnel and copy the tunnel token.
2. Add a Public Hostname in the Cloudflare dashboard:
   - **Domain**: `pod.yourdomain.com`
   - **Service**: `http://wolin:4000` (or `http://127.0.0.1:4000` if running `cloudflared` on the host)
3. Uncomment the `cloudflared` service in `deploy/docker-compose.yml` and set in `.env`:
   ```dotenv
   WOLIN_BASE_URL=https://pod.yourdomain.com
   WOLIN_POD_CLOUD_DOMAIN=yourdomain.com
   CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoi...
   ```
4. Start the stack:
   ```bash
   docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
   ```

### 1.5 Quickstart D: Bare-Metal Linux & Raspberry Pi (`arm64` / `x86_64`) + `systemd`

1. Install build prerequisites (Debian / Ubuntu / Raspberry Pi OS 64-bit):
   ```bash
   sudo apt-get update && sudo apt-get install -y build-essential clang cmake libclang-dev pkg-config curl
   ```
2. Build and install the binary (`install` safely unlinks running binaries):
   ```bash
   cargo build --locked --release -p wolin-server
   TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
   sudo install -m 0755 "${TARGET_DIR}/release/wolin-server" /usr/local/bin/wolin-server
   ```
3. Create dedicated system user and private data directory:
   ```bash
   sudo useradd --system --user-group --home-dir /var/lib/wolin --no-create-home --shell /usr/sbin/nologin wolin
   sudo install -d -m 0700 -o wolin -g wolin /var/lib/wolin /etc/wolin
   sudo cp .env.example /etc/wolin/wolin.env
   sudo chmod 0600 /etc/wolin/wolin.env
   ```
   Update `WOLIN_STORAGE_DIR=/var/lib/wolin` and `WOLIN_LISTEN_ADDR=127.0.0.1:4000` in `/etc/wolin/wolin.env`.
4. Create `/etc/systemd/system/wolin.service`:
   ```ini
   [Unit]
   Description=Wolin Sovereign Solid 0.11 + MCP Pod Server
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=wolin
   Group=wolin
   EnvironmentFile=/etc/wolin/wolin.env
   ExecStart=/usr/local/bin/wolin-server
   Restart=on-failure
   RestartSec=3
   NoNewPrivileges=true
   ProtectSystem=strict
   ProtectHome=true
   PrivateTmp=true
   ReadWritePaths=/var/lib/wolin

   [Install]
   WantedBy=multi-user.target
   ```
5. Enable and verify:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now wolin.service
   curl -fsS http://127.0.0.1:4000/healthz
   ```

### 1.6 Provisioning Your First Pod & Backups

Provision a tenant Pod via `POST /api/pods`:

```bash
curl -fsS -X POST http://127.0.0.1:4000/api/pods \
  -H "Content-Type: application/json" \
  -d '{
    "pod_id": "alice",
    "display_name": "Alice Home Pod",
    "owner_webid": "did:web:alice.example.org"
  }'
```

**Backups**: Stop `wolin-server` cleanly (`docker compose stop wolin` or `sudo systemctl stop wolin`) so RocksDB flushes its WAL, then archive `/data` (contains `blobs/` and `graph/`).

---

## 2. 한국어 가이드

Wolin(`wolin-server`)은 **W3C Solid 0.11 LDP**, **Solid-OIDC + RFC 9449 DPoP**, **Oxigraph RDF/SPARQL 1.1**, **Apache OpenDAL**, **W3C WAC/ACP 인가 엔진**, **Native MCP(`/mcp`, `/mcp/sse`)**를 약 **23 MiB** 단일 네이티브 바이너리에 통합한 소버린 Pod 엔진입니다.

유휴 시 약 **21 MiB RSS** 메모리만 사용하므로 라즈베리파이 4/5(`arm64`), 미니 PC(Intel N100 등), NAS(Synology/QNAP/TrueNAS), 리눅스 홈서버에서 쾌적하게 구동됩니다.

### 2.1 설정 우선순위 및 환경변수 (`WOLIN_*`)

모든 설정은 아래 3단계 우선순위로 결정됩니다:

```text
CLI 플래그  >  WOLIN_* 환경변수  >  내장 기본값
```

| 환경변수 | CLI 플래그 | 기본값 | 설명 |
| :--- | :--- | :--- | :--- |
| `WOLIN_LISTEN_ADDR` | `--listen-addr <IP:PORT>` | `127.0.0.1:4000` | 바인딩 소켓 주소 (`IP:PORT` 리터럴; 컨테이너 기본값 `0.0.0.0:4000`) |
| `WOLIN_HOST` | `--host <IP>` | `127.0.0.1` | 바인딩 IP 리터럴 (`127.0.0.1`, `0.0.0.0`, `::1` 등) |
| `WOLIN_PORT` | `-p`, `--port <PORT>` | `4000` | 바인딩 TCP 포트 |
| `WOLIN_STORAGE_DIR` | `-d`, `--storage-dir <DIR>` / `--in-memory` | *(인메모리)* | 영구 데이터 경로 (`blobs/` + `graph/`, `0700`); `memory` 지정 시 인메모리 |
| `WOLIN_BASE_URL` | `--base-url <URL>` | `http://<host>:<port>` | 외부 공개 정규 Pod Base URL (RDF IRI, `Location`, 디스커버리 기준) |
| `WOLIN_POD_PREFIX` | `--pod-prefix <URI>` | `wolin://pod` | WAC/ACP 정책 엔진 내부 정규 리소스 URI 프리픽스 |
| `WOLIN_POD_CLOUD_DOMAIN` | `--pod-cloud-domain <DOM>` | `wolin.cloud` | `{pod_id}.{domain}` 서브도메인 라우팅용 루트 도메인 |
| `WOLIN_OIDC_ISSUER` | `--oidc-issuer <URL>` | `https://auth.wolin.id` | 신뢰할 Solid-OIDC / ZITADEL 토큰 발급자(Issuer) URL |
| `WOLIN_OIDC_AUDIENCE` | `--oidc-audience <AUD>` | *(없음)* | 선택적 필수 JWT `aud` 클레임 |
| `WOLIN_OWNER_WEBID` | `--owner-webid <URI>` | *(없음)* | 부트스트랩 루트 소유자 WebID 또는 DID (`did:key:...`, `did:web:...`) |
| `WOLIN_REQUIRE_EXPLICIT_DELEGATION` | `--require-explicit-delegation` | `false` | AI 에이전트(`act.sub`) 요청 시 명시적 `DelegationGrant` 요구 여부 |
| `WOLIN_MCP_ENABLED` | `--mcp-enabled <BOOL>` / `--no-mcp` | `true` | Native MCP 게이트웨이(`/mcp`, `/mcp/sse`) 활성화 여부 |
| `WOLIN_MAX_BODY_BYTES` | `--max-body-bytes <BYTES>` | `16777216` | 최대 허용 HTTP 요청 본문 크기 (기본 16 MiB) |
| `WOLIN_MAX_OPEN_PODS` | `--max-open-pods <COUNT>` | `256` | 동시 오픈 허용 Pod별 RocksDB 그래프 스토어 LRU 상한 |
| `WOLIN_DEFAULT_POD_QUOTA_BYTES` | `--pod-quota-bytes <BYTES>` | `1073741824` | Pod당 기본 스토리지 쿼터 바이트 (`1 GiB`) |
| `WOLIN_LOG` / `RUST_LOG` | *(환경변수 전용)* | `info,...` | 구조화 로그 레벨 필터 |

### 2.2 빠른 시작 A: Docker Compose (권장)

```bash
git clone https://github.com/wolin-id/wolin.git
cd wolin
cp .env.example .env

# 이미지 빌드 및 백그라운드 실행 (기본 호스트 바인딩: 127.0.0.1:4000)
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build

# 헬스체크 및 서버 기능 명세 확인
curl -fsS http://127.0.0.1:4000/healthz
curl -fsS http://127.0.0.1:4000/.well-known/wolin
```

- **홈 네트워크(LAN) 직접 접속**: 리버스 프록시 없이 내부망 기기에서 접근하려면 `.env`에서 `WOLIN_HTTP_BIND=0.0.0.0:4000` 및 `WOLIN_BASE_URL=http://<홈서버_LAN_IP>:4000`으로 설정하세요.
- **MCP 비활성화**: 순수 Solid LDP 저장소로만 운영하려면 `.env`에서 `WOLIN_MCP_ENABLED=false`로 설정하세요 (`/mcp`, `/mcp/sse`가 404로 차단됩니다).

### 2.3 빠른 시작 B: Caddy 커스텀 도메인 + 자동 HTTPS 설정

공유기에서 `80`/`443` 포트포워딩이 가능한 환경이라면 내장 Caddy 프로필로 자동 TLS 인증서(Let's Encrypt / ZeroSSL)를 즉시 구성할 수 있습니다:

1. 도메인 DNS `A`/`AAAA` 레코드(예: `pod.example.org`)를 홈서버 공인 IP로 연결합니다.
2. `.env` 파일을 생성합니다 (Caddy 설정을 직접 수정하려면 `cp deploy/Caddyfile.example deploy/Caddyfile` 후 `.env`에 `WOLIN_CADDYFILE=./Caddyfile`을 지정합니다):
   ```bash
   cp .env.example .env
   ```
3. `.env`에 도메인과 인증서 알림 이메일을 입력합니다:
   ```dotenv
   WOLIN_BASE_URL=https://pod.example.org
   WOLIN_POD_CLOUD_DOMAIN=example.org
   WOLIN_PUBLIC_HOST=pod.example.org
   ACME_EMAIL=you@example.org
   ```
4. `caddy` 프로필을 포함해 실행합니다:
   ```bash
   docker compose --env-file .env -f deploy/docker-compose.yml --profile caddy up -d --build
   ```

### 2.4 빠른 시작 C: Cloudflare Tunnel (포트포워딩 불필요 / 통신사 CGNAT 환경)

통신사 공유기 제한이나 아파트 CGNAT 환경으로 인바운드 포트를 열 수 없는 홈서버에 적합합니다:

1. **Cloudflare Zero Trust → Networks → Tunnels**에서 새 터널을 생성하고 토큰을 복사합니다.
2. Public Hostname을 추가하여 `pod.yourdomain.com` → `http://wolin:4000`으로 연결합니다.
3. `deploy/docker-compose.yml` 하단의 `cloudflared` 주석을 해제하고 `.env`에 설정합니다:
   ```dotenv
   WOLIN_BASE_URL=https://pod.yourdomain.com
   WOLIN_POD_CLOUD_DOMAIN=yourdomain.com
   CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoi...
   ```
4. 실행합니다:
   ```bash
   docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
   ```

### 2.5 빠른 시작 D: 리눅스 / 라즈베리파이 네이티브 설치 (`systemd`)

1. 필수 빌드 패키지를 설치합니다 (Debian / Ubuntu / Raspberry Pi OS 64-bit):
   ```bash
   sudo apt-get update && sudo apt-get install -y build-essential clang cmake libclang-dev pkg-config curl
   ```
2. 릴리스 바이너리를 빌드 및 설치합니다 (`cp` 대신 `install`을 사용해 실행 중 교체 시 `Text file busy`를 방지합니다):
   ```bash
   cargo build --locked --release -p wolin-server
   TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
   sudo install -m 0755 "${TARGET_DIR}/release/wolin-server" /usr/local/bin/wolin-server
   ```
3. 전용 비루트 계정(`wolin`)과 `0700` 데이터 디렉터리를 생성한 뒤 위의 **1.5절** 예시와 동일하게 `/etc/systemd/system/wolin.service`를 등록하고 `sudo systemctl enable --now wolin.service`로 기동합니다.

### 2.6 첫 Pod 생성 및 백업

```bash
curl -fsS -X POST http://127.0.0.1:4000/api/pods \
  -H "Content-Type: application/json" \
  -d '{
    "pod_id": "alice",
    "display_name": "Alice Home Pod",
    "owner_webid": "did:web:alice.example.org"
  }'
```

**백업 안내**: 컨테이너(`docker compose stop wolin`) 또는 데몬(`sudo systemctl stop wolin`)을 정상 종료해 Oxigraph RocksDB WAL을 플러시한 뒤 `/data`(`blobs/` 및 `graph/`) 디렉터리를 압축 보관하세요.
