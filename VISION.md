# WOLIN (月印) : One Identity. Infinite Reflections.
> **"애플리케이션은 생겨나고 사라지지만, 아이덴티티는 지속되고 데이터는 흐른다."**
> *(Applications come and go. Identity persists. Data flows.)*

---

## 1. 프로젝트 배경과 시대적 소명 (Background & Calling)

### 1.1 Web의 왜곡과 AI 시대의 새로운 식민화
1. **웹의 원초적 이상 상실:**
   팀 버너스-리(Tim Berners-Lee)가 구상한 월드와이드웹(WWW)은 누구나 동등하게 읽고 쓰는 탈중앙화된 공간이었습니다. 그러나 Web 2.0 시대를 거치며 소수의 거대 플랫폼(빅테크)이 사용자의 아이덴티티와 데이터를 플랫폼 내부에 가두고 광고와 락인(Lock-in)의 수단으로 삼았습니다.
2. **투기적 Web3의 한계:**
   이에 대항해 등장한 기존 'Web3'는 데이터 주권과 탈중앙화라는 기치를 내걸었으나, 과도한 금융 투기, 토큰 경제(Tokenomics), 비싼 가스비, 느린 트랜잭션, 파편화된 지갑 UX로 인해 일반 대중과 실제 기업 인프라로부터 철저히 유리되었습니다.
3. **AI 에이전트 시대의 새로운 데이터 수탈:**
   AI Agent와 LLM이 인간의 모든 일상과 업무를 대행하는 시대로 진입했습니다. 현재의 구조는 사용자의 사적 기억, 기업의 영업비밀, 인간의 창작물이 모델 학습 데이터라는 명목으로 소수 AI 기업의 데이터센터로 흡수되는 '2차 데이터 식민화'를 초래하고 있습니다. 에이전트가 서비스를 대신 써주는 시대가 올수록, 에이전트 뒤에 있는 인간의 데이터 주권은 더욱 완전히 박탈됩니다.

---

## 2. 인류에게 진정으로 필요한 Web3의 정의 (The True Web3 for Humanity)

인류에게 필요한 참된 Web3는 **"토큰 투기판이 아니라, 인간의 디지털 실존을 보장하는 영속적 인프라"**입니다.

### 2.1 3대 핵심 철학

1. **소버린 시맨틱 백본 (Sovereign Semantic Backbone):**
   - 블록체인 가스비 없이도 암호학적으로 무결성이 입증되는 개인/기업 소유의 데이터 포드(Pod).
   - 파일 단위 덤프가 아니라, 인간과 기계가 모두 이해할 수 있는 의미(Semantic Graph, RDF/SPARQL)로 조직화된 데이터.
2. **월인천강(月印千江)의 신원 체계 (One Identity, Infinite Reflections):**
   - 하나의 달이 수천 개의 강에 각기 비추듯, 하나의 확고한 디지털 주체(Identity)가 기업, 정부, SNS, AI 서비스에 맞춤형 투영(Projection)으로 연결됩니다.
   - 서비스가 폐업하거나 플랫폼이 계정을 정지하더라도, 나의 아이덴티티와 데이터 역사는 파괴되지 않고 유지됩니다.
3. **에이전트 권한의 한시적 위임 (Dynamic Delegation & Zero-Trust MCP):**
   - AI 에이전트는 사용자의 포드에 전권을 갖지 않습니다.
   - 오직 특정 작업 수행에 필요한 최소한의 시맨틱 데이터만을 일회성 가상 뷰(Projection) 형태로 인가받고, 작업 완료 시 권한은 즉시 소멸합니다.

---

## 3. 시장 현황 및 기술적 기회 분석 (Market Landscape & Opportunity)

| 기술 및 영역 | 현재 상태 및 한계 | WOLIN의 돌파구 (White Space) |
| :--- | :--- | :--- |
| **W3C Solid 생태계** | • 공식 구현체(CSS, Node.js)는 학술/데모용으로 무겁고 느림 (RAM >300MB)<br>• 엔터프라이즈 멀티테넌시 및 실시간성 부재 | • **Rust 기반 단일 바이너리 엔진** 구축<br>• 메모리 30MB 이하 저자원 엣지/클라우드 구동<br>• 기업용 OpenDAL 스토리지 결합 |
| **분산 신원 (DID / VC)** | • 지갑 설치 허들 및 기존 사내 IdP(SSO)와의 단절<br>• 실제 데이터 스토리지와의 연동 결여 | • **ZITADEL / Keycloak OIDC 페더레이션**<br>• WebID + DID(did:key, did:nostr) + DPoP 동시 지원 |
| **AI 에이전트 인터페이스 (MCP)** | • 단순 REST/파일 도구 위주로 구성<br>• 데이터 거버넌스 및 세분화 권한 모델 전무 | • **Native MCP Semantic Gateway**<br>• 에이전트 전용 SPARQL/GraphQL 프로젝션 도구 제공 |
| **블록체인 / 크립토** | • 온체인 트랜잭션 비용 및 확장성 한계<br>• 프라이버시(영지식) 구현의 복잡성 | • **오프체인 시맨틱 그래프 + 암호학적 서명 증명**<br>• 금융이 아닌 '데이터 흐름과 신뢰'에 집중 |

---

## 4. WOLIN 아키텍처 비전 (System Architecture)

```
┌────────────────────────────────────────────────────────────────────────┐
│                   AI Agents / Applications / Services                  │
│               (Claude, OpenAI, Cursor, Enterprise ERP, Web)            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Model Context Protocol (MCP) / HTTP LDP
┌───────────────────────────────────▼────────────────────────────────────┐
│                  WOLIN MCP & Policy Gateway (PDP / PEP)                │
│   • Semantic Projection: 요청 맥락에 맞는 가상 RDF 서브그래프 생성     │
│   • Dynamic Consent: 시간/목적 제한 일회성 위임 (RFC 9449 DPoP)       │
│   • Zero-PII Selective Disclosure: 민감 데이터 마스킹 및 선택적 공개   │
├────────────────────────────────────────────────────────────────────────┤
│                  Federated Trust & Identity Mesh                       │
│   • Enterprise IAM: ZITADEL, Keycloak, Entra ID (OIDC / OAuth2)        │
│   • Sovereign Identity: WebID, W3C DID (did:key, did:nostr)            │
│   • Cryptographic Claims: Ed25519, DPoP 비대칭키 증명                   │
├────────────────────────────────────────────────────────────────────────┤
│                  High-Performance Semantic Core                        │
│   • Embedded Engine: Oxigraph (RocksDB 기반 RDF 쿼드 스토어 / SPARQL 1.1)│
│   • Protocol Pipeline: W3C Solid Protocol 0.11 (LDP / WAC / ACP)       │
├────────────────────────────────────────────────────────────────────────┤
│                  Multi-Backend Storage Virtualization                  │
│   • Apache OpenDAL Engine: Local NVMe, AWS S3, Cloudflare R2, Ceph     │
│   • Tamper-Evident Ledger: Git-mark 기반 변경 이력 영속성              │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 5. 실행 원칙 및 로드맵 (Guiding Principles)

1. **Rust AOT First:** 고성능, 무가비지컬렉션, 엄격한 메모리 안전성 및 단일 바이너리 배포 원칙.
2. **Pragmatic Convergence:** 무의미한 바퀴 재발명 금지. 시맨틱 쿼리는 `oxigraph`, 스토리지는 `opendal`, 프로토콜 규격은 `manas` 크레이트를 흡수하고, 핵심 독자 IP인 **AI Agent MCP Gateway와 동적 인가 엔진**에 집중.
3. **No-Crypto Sane Web3:** 투기용 코인 발행 배제. 암호학(Cryptography)은 금융 투기가 아니라 '주권 증명과 신뢰 검증'을 위해서만 사용.
