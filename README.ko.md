<div align="center">

# Wolin (월인천강 · 月印千江)

**One Identity. Infinite Reflections. — Rust 기반 W3C Solid 0.11 소버린 팟 클라우드 & 셀프호스팅 엔진**

**[ English ](README.md)** • **[ 한국어 ](README.ko.md)**

</div>

---

Wolin(`wolin-id/wolin`)은 **W3C Solid 0.11**, **Solid-OIDC + RFC 9449 DPoP(`at+jwt`)**, **Per-Pod Oxigraph RDF/SPARQL 1.1**, **Apache OpenDAL**, **W3C WAC/ACP 인가 엔진**, 그리고 **Native MCP(`/mcp`, `/mcp/sse`)**를 통합한 초경량 단일 바이너리 Rust 엔진입니다.

하나의 코어 엔진으로 다음 두 가지를 모두 지원합니다:
1. **홈서버 / 라즈베리파이 / NAS / 사내 구축용 셀프호스팅 Pod 서버**
2. **매니지드 Wolin Pod Cloud(`https://pod.wolin.id` & `https://{handle}.wolin.id/`) 멀티테넌트 프로덕션 데이터 플레인** (`https://auth.wolin.id` 연동)

---

## 1. 크레이트 아키텍처

```text
wolin/
├── crates/
│   ├── wolin-core/       # 도메인 원시 타입: WebId, Principal, ResourceUri, WolinError
│   ├── wolin-storage/    # OpenDAL (블롭) + Per-Pod Oxigraph RocksDB (Bounded LRU 256 + 1 GiB 쿼터)
│   ├── wolin-identity/   # W3C DID, Solid-OIDC, JwksSignatureVerifier, RFC 9449 DPoP & at+jwt 검증
│   ├── wolin-policy/     # W3C WAC (.acl) & Inrupt ACP 듀얼 PDP + 스코프 위임(DelegationGrant)
│   ├── wolin-mcp/        # 스코프 제한 시맨틱 투영 게이트웨이 & Zero-PII 마스킹 (/mcp, /mcp/sse)
│   └── wolin-server/     # Axum 0.8 + Tokio Solid LDP, 멀티테넌트 라우터, Tombstone & 302 에셋 오프로딩
```

## 2. 프로덕션 핵심 기능 및 실측 풋프린트

- **Per-Pod 물리 격리 & 쿼터**: Pod별 독립 Oxigraph RocksDB(`graph/pods/{pod_id}/`), Bounded LRU 핸들 캐시(기본 `256`), Pod당 기본 `1 GiB` 스토리지 쿼터(`$0` Free Tier 기본 제공, 초과 시 `413`/`507`).
- **핸들 보안 & 영구 Tombstone**: `3..32`자 소문자 영숫자 규칙, 약 180개 기본 예약 핸들 차단(`--reserved-pods` 확장 지원), 삭제/은퇴 Pod 영구 동결(`410 Gone`).
- **무-송신료(Zero-Egress) 서명 에셋 오프로딩**: DPoP + WAC/ACP 인가 통과 후 `256 KiB` 이상 `NonRDFSource`를 60초 유효 `HMAC-SHA256`(`wolin-asset-v1`) 서명 URL로 `302 Found` 리다이렉트하여 Cloudflare R2에서 직접 스트리밍.
- **암호학적 JWKS & `at+jwt` 검증**: `JwksSignatureVerifier`(`--oidc-jwks-json` / `WOLIN_OIDC_JWKS_JSON`), DPoP `jti` 리플레이 캐시, `id_token` 오용을 원천 차단하는 `typ: "at+jwt"` 헤더 검증.
- **실측 풋프린트 & 테스트 검증**:
  - 단일 정적 바이너리: **~17–23 MiB** (내장 Oxigraph RocksDB, OpenDAL, Axum 0.8, Rustls)
  - 메모리 사용량: **15.3 MiB RSS** (`--in-memory` 모드, ~5.9 ms 기동) / **21.4 MiB RSS** (영구 모드 대기)
  - 테스트 검증: 워크스페이스 전체 **85/85** 테스트 통과 (`cargo test --locked --workspace`).

## 3. 빠른 시작 (`--in-memory` 샌드박스 & 셀프호스팅)

> 별도의 공용 Devnet 없이 로컬에서는 `wolin-server --in-memory`로 즉시 개발·테스트하고, 클라우드 실환경은 [`https://auth.wolin.id`](https://auth.wolin.id) / [`https://pod.wolin.id`](https://pod.wolin.id)의 **`$0` Free Tier (`1 GiB`)**를 바로 사용할 수 있습니다. Docker Compose, Caddy 자동 HTTPS, Cloudflare Tunnel, `systemd` 가이드는 **[docs/SELF_HOSTING.md](docs/SELF_HOSTING.md)**를 참고하세요.

```bash
# 전체 워크스페이스 테스트 실행 (85개 통과)
cargo test --locked --workspace

# 1. 외부 의존성 0개 로컬 인메모리 샌드박스 실행 (~6 ms 기동)
cargo run --release -p wolin-server -- --in-memory --port 4000

# 2. 커스텀 도메인을 연결한 영구 셀프호스팅 서버 실행
cargo run --release -p wolin-server -- \
  --host 0.0.0.0 \
  --port 4000 \
  --storage-dir ./data/wolin \
  --base-url https://pod.example.org \
  --pod-cloud-domain example.org
```

## 4. 공식 SDK 및 관련 저장소

- **공식 웹 포털 & 개발자 허브**: [`wolin-id/web`](https://github.com/wolin-id/web) ([wolin.id](https://wolin.id), `/llms.txt`, `/llms-full.txt`)
- **아키텍처 & 전략 문서**: [`wolin-id/docs`](https://github.com/wolin-id/docs)
- **AI 에이전트 공식 스킬**: [`wolin-id/skills`](https://github.com/wolin-id/skills)
- **3D 메타버스 월드 스타터**: [`wolin-id/metaverse-starter`](https://github.com/wolin-id/metaverse-starter)
- **5대 공식 SDK**:
  - TypeScript / React: [`wolin-id/sdk-js`](https://github.com/wolin-id/sdk-js) (`@wolin-id/client`, `@wolin-id/react`)
  - Python 3.11+: [`wolin-id/sdk-python`](https://github.com/wolin-id/sdk-python) (`wolin-id`)
  - Unity C#: [`wolin-id/sdk-unity`](https://github.com/wolin-id/sdk-unity) (`id.wolin.unity`)
  - Swift 6: [`wolin-id/sdk-swift`](https://github.com/wolin-id/sdk-swift) (`WolinKit`)
  - Kotlin / Android / JVM: [`wolin-id/sdk-kotlin`](https://github.com/wolin-id/sdk-kotlin) (`id.wolin:sdk-kotlin`)

## 5. 라이선스

본 프로젝트는 아래 두 라이선스 중 하나를 선택해 이용할 수 있습니다:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))
