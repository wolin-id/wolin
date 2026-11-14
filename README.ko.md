<div align="center">

# Wolin (월인 · 月印千江)

**One Identity. Infinite Reflections. — Rust 기반 W3C Solid 0.11 소버린 팟 클라우드 & 셀프호스팅 엔진**

**[ English ](README.md)** • **[ 한국어 ](README.ko.md)**

</div>

---

Wolin(`wolin-id/wolin`)은 **W3C Solid 0.11**, **Solid-OIDC + RFC 9449 DPoP**, **Oxigraph RDF/SPARQL 1.1**, **Apache OpenDAL**, 그리고 **W3C WAC/ACP 인가 엔진**을 통합한 초경량 단일 바이너리 Rust 엔진입니다.

하나의 코어 엔진으로 다음 두 가지를 모두 지원합니다:
1. **홈서버 / 사내 구축용 셀프호스팅 Pod 서버**
2. **매니지드 Wolin Pod Cloud([wolin.id](https://wolin.id)) 멀티테넌트 데이터 플레인**

---

## 1. 크레이트 아키텍처

```text
wolin/
├── crates/
│   ├── wolin-core/       # 도메인 원시 타입: WebId, Principal, ResourceUri, WolinError
│   ├── wolin-storage/    # 듀얼 플레인: Apache OpenDAL (블롭) + Oxigraph (RDF/SPARQL 1.1)
│   ├── wolin-identity/   # W3C DID, Solid-OIDC + DPoP, ZITADEL/OIDC JWT 검증기
│   ├── wolin-policy/     # W3C WAC (.acl) & ACP (Access Control Policy) 듀얼 PDP
│   ├── wolin-mcp/        # 스코프 제한 시맨틱 투영 게이트웨이 & Zero-PII 마스킹
│   └── wolin-server/     # Axum 0.8 + Tokio 기반 Solid LDP, 멀티테넌트 라우팅 데몬
```

## 2. 실측 성능 및 풋프린트

- **단일 정적 바이너리**: ~17 MiB (내장 Oxigraph RocksDB, OpenDAL, Axum 0.8, Rustls)
- **메모리 사용량**:
  - In-Memory 모드: **15.3 MiB RSS** (~5.9 ms 기동)
  - 영구 RocksDB + FS 모드: **21.4 MiB RSS** (대기) / **23.9 MiB RSS** (실부하)
- **테스트 검증**: 워크스페이스 전체 **63/63** 테스트 통과 (`cargo test --locked --workspace`).

## 3. 빠른 시작 (Quickstart)

```bash
# 전체 워크스페이스 테스트 실행
cargo test --locked --workspace

# 커스텀 도메인을 연결한 영구 셀프호스팅 서버 실행
cargo run --release -p wolin-server -- \
  --host 0.0.0.0 \
  --port 4000 \
  --storage-dir ./data/wolin \
  --base-url https://pod.example.org \
  --pod-cloud-domain example.org
```

## 4. 관련 저장소

- **공식 웹 포털**: [`wolin-id/web`](https://github.com/wolin-id/web) ([wolin.id](https://wolin.id))
- **아키텍처 & 전략 문서**: [`wolin-id/docs`](https://github.com/wolin-id/docs)

## 5. 라이선스

본 프로젝트는 아래 두 라이선스 중 하나를 선택해 이용할 수 있습니다:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))
