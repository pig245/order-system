# 한산 전용 발주 관리 시스템

Google Apps Script(GAS) 기반 발주 시스템을 **Cloudflare Workers + Hono.js + D1(SQLite)** 구조로 완전히 마이그레이션한 풀스택 웹 애플리케이션입니다.

## 📁 프로젝트 구조

```
google/
├── wrangler.toml           # Cloudflare Workers 설정 (D1, Cron, Vars)
├── package.json            # 의존성 및 스크립트
├── schema.sql              # D1 데이터베이스 스키마 (8개 테이블)
├── README.md               # 이 문서
├── .gitignore
├── public/                 # 정적 에셋 (CSV 샘플 등)
│   └── matching-sample.csv # 유종 매칭표 업로드 예시
└── src/
    ├── index.js            # Hono.js 백엔드 API (단일 파일, ~1700줄)
    └── pages/              # 프론트엔드 HTML (Worker가 직접 서빙)
        ├── login.html      # 로그인 (관리자/거래처 통합)
        ├── index.html      # 거래처 발주 화면
        ├── admin.html      # 관리자 대시보드
        └── db.html         # D1 데이터베이스 GUI (별도 페이지)
```

## 🏗️ 아키텍처 특징

| 영역 | 기술 스택 | 설명 |
|------|-----------|------|
| **런타임** | Cloudflare Workers (V8 Isolates) | 전 세계 에지에서 저지연 실행 |
| **프레임워크** | Hono.js 4.x | 경량, 타입 안전, 미들웨어 지원 |
| **데이터베이스** | Cloudflare D1 (SQLite) | 서버리스 SQL, ACID 트랜잭션 |
| **인증** | HMAC-SHA256 서명 토큰 | 상태 없음, 만료/폐기 검증 내장 |
| **프론트엔드** | Vanilla JS + Tailwind CDN | 빌드 단계 없음, Worker가 HTML 직접 서빙 |
| **정적 파일** | `public/` 폴더 | `wrangler dev --remote`시 Assets 번들링 |
| **외부 연동** | Google Sheets API | 발주 저장 시 D1 + 시트 이중 기록 (fail-soft) |



## 🗄️ 데이터베이스 스키마 (8개 테이블)

```sql
settings          -- 키-값 설정 저장
admins            -- 관리자 계정 (초기 비밀번호 1111)
clients           -- 마스터 거래처 (지역계정의 부모)
client_accounts   -- 지역별 하위 계정 (독립 로그인, 지역 고정)
oil_matching      -- 유종 매칭표 (품명→유종, 거래처별 제한)
orders            -- 발주 내역 (record_id PK, 확정/수정횟수 관리)
auth_tokens       -- 로그인 토큰 (HMAC 서명, 만료/폐기 관리)
login_attempts    -- 브루트포스 방어 (IP/계정별 5회/10분)
```

### 주요 설계 포인트
- **마스터/지역계정 분리**: `clients`(마스터) ↔ `client_accounts`(지역) 1:N
- **지역 락(Lock)**: 지역계정 생성 시 해당 지역은 마스터 계정에서 **자동 차단** (`blockedRegions` 메커니즘)
- **미등록 품목 허용**: `oil_matching`에 없는 품목도 발주 가능 → 유종 `미등록`으로 저장
- **수정 횟수 제한**: 발주당 최대 2회 수정, 확정 후 수정 불가

## ⚙️ 설정 (`wrangler.toml`)

```toml

[[d1_databases]]
binding = "DB"
database_name = "Database_name input"
database_id = "Database_id input"

[vars]
ORDER_TIME_ZONE         = "Asia/Seoul"    # 발주 시간 계산용
ORDER_ENTRY_START_HOUR  = "0"             # 발주 시작 시각 (0~23)
ORDER_ENTRY_CUTOFF_HOUR = "16"            # 발주 마감 시각 (1~24)
TOKEN_SECRET            = "change-me"     # 토큰 서명용 (배포시 변경 필수)

# Google Sheets 이중 저장 
GOOGLE_SERVICE_ACCOUNT_EMAIL = "서비스계정@프로젝트.iam.gserviceaccount.com"
GOOGLE_PRIVATE_KEY           = "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n"
GOOGLE_SPREADSHEET_ID        = "스프레드시트-ID"
GOOGLE_SHEET_NAME            = "sheet1"

[triggers]
crons = ["0 18 * * *"]  # 매일 18:00 만료/폐기 토큰 정리
```

## 🚀 실행 방법

### 1. 의존성 설치(POWERSHELL 사용)
```bash
npm install
```

### 2. Cloudflare 로그인 & D1 생성(Cloudflare 아이디 생성 먼저 D1 이름은 알아서))
```bash
npx wrangler login
npx wrangler d1 create "원하는 DB이름"
```
→ 출력된 `database_id`를 `wrangler.toml`의 `database_id`에 복사

### 3. 스키마 적용 (원격/로컬 선택)
```bash
npm run db:remote   # 원격 D1에 적용 (배포 및 운영용)
npm run db:local    # 로컬 SQLite에 적용 (개발용)
```

### 4. 개발 서버 실행
```bash
npm run dev         # wrangler dev --remote (원격 D1 사용)
npm run dev:local   # wrangler dev (로컬 D1 사용)
```

### 5. 배포
```bash
npm run deploy      # wrangler deploy (프로덕션 배포)
```

## 🔐 초기 계정

| 구분 | 아이디/이름 | 비밀번호 | 비고 |
|------|-------------|----------|------|
| 관리자 | `admin` (고정) | `1111` | 로그인 화면에서 '관리자 로그인' 선택 |
| 거래처 | 관리자 페이지에서 생성 | `1111` (기본) | 비워두면 1111 |
| 지역별 | 관리자 페이지에서 생성 | `1111` (기본) | 비워두면 1111, 지역 고정 |

## 🌐 페이지 라우팅

|경로      | 용도 | 인증 |
|-------  |------|------|
| `/` | 로그인 페이지 리다이렉트 | - |
| `/login` | 통합 로그인 (관리자/거래처 탭) | - |
| `/order` | 거래처 발주 화면 | 거래처/지역계정 토큰 ||

> 관리자 페이지의 **"D1 관리 열기"** 버튼을 누르면 토큰을 포함한 `/db?token=...`로 이동합니다.

## 📡 주요 API 엔드포인트

### 인증
| 메서드 | 경로 | 설명 |
|--------|------|------|
| `POST` | `/api/auth/client` | 거래처/지역계정 로그인 |
| `POST` | `/api/auth/admin` | 관리자 로그인 |
| `POST` | `/api/auth/logout` | 토큰 폐기 |
| `GET` | `/api/session` | 현재 세션/권한/차단지역 조회 |

### 거래처 (발주)
| 메서드 | 경로 | 설명 |
|--------|------|------|
| `GET` | `/api/client/products` | 허용 품목+유종 조회 |
| `GET` | `/api/client/orders` | 내 발주 내역 조회 (차단 지역 제외) |
| `POST` | `/api/client/orders` | 발주 저장 (D1 저장 후 Google Sheets append) |
| `PATCH` | `/api/client/orders/:id` | 수량 수정 (최대 2회) |
| `DELETE` | `/api/client/orders/:id` | 발주 삭제 |
| `POST` | `/api/client/password` | 본인 비밀번호 변경 |

### 관리자
| 메서드                  | 경로                              | 설명                     |
|-------------------------|-----------------------------------|--------------------------|
| `GET`                   | `/api/admin/orders`               | 기간별 발주 조회 (확정 대기) |
| `POST`                  | `/api/admin/orders/confirm`       | 기간별 발주 확정         |
| `GET`                   | `/api/admin/excel`                | 확정 내역 XLSX 다운로드  |
| `GET/POST/PUT/DELETE`   | `/api/admin/products`             | 유종 매칭 CRUD           |
| `POST`                  | `/api/admin/products/import`      | CSV 업로드 (업서트)      |
| `POST`                  | `/api/admin/clients`              | 마스터 거래처 생성 + 토큰 발급 |
| `POST`                  | `/api/admin/accounts`             | **지역계정 생성** (자동 차단 지역 등록) |
| `GET/POST/PUT/DELETE`   | `/api/admin/db/:table`            | D1 GUI용 테이블 조작     |
| `POST`                  | `/api/admin/password`             | 관리자 비밀번호 변경     |

## 💡 핵심 비즈니스 로직

### 1. 지역계정 생성 시 마스터 차단 (`blockedRegions`)
```
마스터 '경일' 생성
   ↓
지역계정 '경일-부산' 생성 (client_accounts에 지역='부산' 저장)
   ↓
마스터 '경일' 로그인 시 → session.blockedRegions = ['부산']
   ↓
/api/client/orders 조회/저장/수정/삭제 시 '부산' 지역 자동 제외
```
→ 지역계정이 전담하는 지역의 발주는 마스터가 **볼 수도, 만질 수도 없음**

### 2. 발주 시간 윈도우 (서버 강제)
- `ORDER_ENTRY_START_HOUR` ~ `ORDER_ENTRY_CUTOFF_HOUR` (기본 00:00~16:00)
- 마감 시각 이후: **발주 추가/수정/삭제 API 모두 400 에러 반환**
- 프론트는 1분마다 `/api/order-window` 폴링해 UI 동기화

### 3. 미등록 품목 처리
- `oil_matching`에 없는 품목도 발주 허용
- 저장 시 `oil = '미등록'`으로 기록 → 관리자가 나중에 매칭표에서 업데이트 가능

### 4. Google Sheets 이중 저장 (fail-soft)
발주가 `POST /api/client/orders` 로 들어오면:

1. **D1 `orders` 테이블에 먼저 저장** (이게 원본)
2. 같은 행을 **Google Sheets API `values.append`** 로 지정 탭에 추가
3. 시트 연동이 실패해도 **D1 저장은 성공으로 유지** (콘솔에 `[Google Sheets]` 로그만 남김)

시트에 쌓이는 열 순서:

```
년도 | 월 | 일 | 거래처 | 지역 | 품명 | 유종 | 수량 | 생성시각(ISO)
```

#### Google Sheets API 활성화 (403 `SERVICE_DISABLED` 해결)
1. [Google Cloud Console](https://console.cloud.google.com/) 접속 후 해당 GCP 프로젝트 선택
2. **API 및 서비스 > 라이브러리 > Google Sheets API** 검색
3. **[사용 설정]** 클릭
4. 활성화 직후 **2~3분 대기** 후 재시도
5. 직접 링크: [sheets.googleapis.com overview](https://console.developers.google.com/apis/api/sheets.googleapis.com/overview)

#### 서비스 계정 + 시트 공유
1. **IAM 및 관리자 > 서비스 계정 > 만들기** → JSON 키 발급
2. JSON의 `client_email` → `GOOGLE_SERVICE_ACCOUNT_EMAIL`
3. `GOOGLE_PRIVATE_KEY`에는 줄바꿈을 **어느 방식으로든** 넣어도 됩니다. `\nMII...`처럼 리터럴 `\n`이 포함된 채 그대로 넣어도 되고, 실제 줄바꿈이 포함된 PEM 전문이나 `wrangler secret put`으로 넣어도 됩니다. 워커가 리터럴/실제 줄바꿈과 공백을 모두 제거한 뒤 디코딩합니다.
4. 대상 스프레드시트 **[공유] → 서비스 계정 이메일 → 편집자**
5. `GOOGLE_SPREADSHEET_ID` = 시트 URL `/d/{이 값}/edit`
6. `GOOGLE_SHEET_NAME` = 하단 탭 이름과 **완전히 동일**해야  (예: sheet1)

개인키는 가능하면 `wrangler.toml` 대신 시크릿으로 넣는다.

```bash
npx wrangler secret put GOOGLE_PRIVATE_KEY
```

### 5. 토큰 구조 (HMAC-SHA256)
```
payload = { id, role, client, label, accountId, loginId, accountRegion, iat, exp }
token   = base64url(payload) + '.' + base64url(HMAC_SHA256(secret, payload))
```
- `auth_tokens` 테이블에 `token_id` 기준으로 저장 (만료/폐기 검증용)
- 관리자 토큰 7일, 거래처 토큰 30일 TTL

## 📂 프론트엔드 구조 (각 HTML 독립 실행)

| 파일 | 핵심 기능 |
|------|-----------|
| `login.html` | 관리자/거래처 탭 전환, 세션스토리지 토큰 관리 |
| `index.html` | 발주 입력/미리보기/저장, 조회·수정 모달, 지역/품명 자동완성 |
| `admin.html` | 기간 확정/엑셀, 품목/CSV, 거래처·지역계정/토큰 관리, **D1 관리 버튼** |
| `db.html` | **테이블 탭 전환, 200행 페이징, 셀 인라인 편집(PUT), PK 읽기전용** |

> 모든 `fetch` 호출은 `Authorization: Bearer <token>` + `X-Auth-Token` 헤더 사용

## 🔧 개발 팁

### 로컬에서 비밀 변경 테스트
```bash
# 관리자 비밀번호 변경
curl -X POST http://127.0.0.1:8787/api/admin/password \
  -H "Authorization: Bearer <admin_token>" \
  -d '{"currentPassword":"1111","newPassword":"new123"}'
```

### CSV 업로드 포맷 (`public/matching-sample.csv` 참고)
```csv
품명,유종,제한 거래처
하이골드,대두,
프리미엄유,카놀라,경일
콩기름,대두,"경일,성규"
```
- `제한 거래처` 비우면 전체 거래처 사용 가능
- 관리자 페이지 "유종 매칭표 CSV 업로드" 버튼으로 업로드 (업서트)

### D1 콘솔 직접 조회
```bash
npx wrangler d1 execute hansan-order-system --remote --command "SELECT * FROM orders"
```

## ⚠️ 주의사항 

1. **D1 GUI 테이블 수정**: 비밀번호 해시/솔트 컬럼(`password_hash`, `password_salt`)은 **직접 수정하지 마세요**. 인증 깨짐.
2. **토큰 시크릿**: `TOKEN_SECRET`은 배포 전 반드시 강력한 랜덤 값으로 변경.
3. **타임존**: `ORDER_TIME_ZONE`이 `Asia/Seoul` 고정. 서버 시간이 KST 기준.

## 📄 라이선스

내부 프로젝트용. 자유롭게 수정/배포 가능.

---

> **최종 업데이트**: 2026-09-08  
> **구현 완료 기능**: 전체 인증/발주/관리자/D1 GUI, 지역계정 차단 로직, 미등록 품목 예외, 발주 시간 윈도우, XLSX 다운로드, CSV 업로드, 토큰 관리, 브루트포스 방어, Google Sheets 이중 저장
