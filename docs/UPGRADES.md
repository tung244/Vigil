# Vigil — Nhật ký nâng cấp (UPGRADES)

> File này ghi lại **chi tiết** các đợt nâng cấp sau v1, để khi quay lại project sau
> một thời gian, đọc lại vẫn hiểu được: đợt đó làm gì, tại sao làm, hoạt động ra
> sao, và code nằm ở file nào.
>
> Quy ước: mỗi đợt nâng cấp là một mục lớn (Món 1, 2, 3...). Mỗi mục có: Mục tiêu,
> Thay đổi chi tiết (kèm file), Cách hoạt động, Cách kiểm chứng, và Ghi chú/Giới hạn.

---

## Món 2 — Wazuh-style UI revamp (hoàn thành)

> Làm trước Món 1 và 3 theo quyết định của chủ project (cần mặt tiền demo đẹp trước).

### Mục tiêu

Biến dashboard React từ "đồ án sinh viên" thành giao diện có cảm giác của một SOC
tool thật (lấy cảm hứng từ Wazuh/OpenSearch Dashboards): dark theme, bảng alert
dày đặc với severity có màu, MITRE ATT&CK heatmap, và flyout chi tiết khi click
vào một alert. Chỉ học **pattern UI** của Wazuh, không copy branding/assets.

### Thay đổi chi tiết

**W1 — Backend: 2 endpoint thống kê mới** (commit `db0eee2`)

- `src/Vigil.Api/Endpoints/StatsEndpoints.cs` — map group `/api/stats`:
  - `GET /api/stats` → KPI tổng hợp: `totalJobs`, `totalReports`,
    `jobsByStatus` (queued/filtering/analyzing/done/failed), `reportsBySeverity`
    (low/medium/high/critical), `avgRiskScore` (làm tròn 2 chữ số), `last24hJobs`.
    Đếm bằng `GroupBy` translate xuống SQL, không kéo data về RAM.
  - `GET /api/stats/mitre` → aggregate toàn bộ `MitreTechniques` (jsonb) của mọi
    report: parse từng mảng technique ID, đếm tần suất, gắn tactic. Trả
    `{techniques: [{techniqueId, tactic, count}], tactics: [...]}` với `tactics`
    đã sắp theo thứ tự kill-chain.
- `src/Vigil.Core/Domain/MitreTacticMap.cs` — bảng map tĩnh ~45 technique
  email/cloud → tactic (vd T1566.x → Initial Access, T1078.004 → Persistence).
  Sub-technique lạ fallback về parent (`T1059.001` → `T1059`), không có nữa thì
  `"Unknown"`. Có comment "extend as needed" — thêm technique mới chỉ là thêm
  một dòng vào map.
- Test: `tests/Vigil.IntegrationTests/StatsEndpointsTests.cs` (3 test, assert
  tương đối vì DB test dùng chung cho test chạy song song).

**W2 — Design foundation** (commit `aab32dd`)

- `frontend/index.html` — thêm `class="dark"` tĩnh: dark theme là mặc định
  (Wazuh là dark-only; toàn bộ trang đã có sẵn `dark:` variants nên tự hưởng,
  không cần sửa từng trang).
- `frontend/tailwind.config.js` — nền dark đổi sang navy-charcoal `#0b0f19`
  (trước là nâu `#221610`); thêm palette `severity-critical/high/medium/low`.
- `frontend/src/components/badges.tsx` (mới) — component dùng chung cho cả app:
  - `SeverityBadge`: critical đỏ / high cam / medium vàng / low sky, dạng chip
    viền mờ (`bg-{color}-500/15 + border-{color}-500/40`) — đọc tốt trên nền dark.
  - `StatusBadge`: Done/Failed/Analyzing/Queued; trạng thái đang chạy có dot ping.
  - `Mono`: span monospace cho IOC, IP, hash, report ID.
  - Helpers `normalizeSeverity`, `severityFromRisk`.

**W3 — Dense alerts table** (commit `57e226d`)

- `frontend/src/pages/Metrics.tsx` — bảng "Recent Investigations" viết lại thành
  alerts table kiểu SOC: padding nhỏ (`px-2 py-1.5`), font 12px, cột Severity
  dùng `SeverityBadge`, Status dùng `StatusBadge`, verdict thành chip.
  Sort asc/desc ở cột Risk Score và Time; filter dropdown theo severity và
  verdict. Pagination đếm trên tập **đã filter** (tránh trang rỗng khi lọc).
- `frontend/src/services/api.ts` — adapter `recent_reports` bổ sung field
  `severity` và `created_at` để phục vụ sort/filter.

**W4 — MITRE ATT&CK heatmap** (commit `fea07e0`)

- `frontend/src/components/MitreHeatmap.tsx` (mới) — lưới heatmap:
  cột = tactic (đúng thứ tự kill-chain từ API, kể cả "Unknown"), ô = technique
  thuộc tactic đó (sort theo count giảm dần trong cột). Màu ô đậm dần theo
  `count/max` (sky-950 → sky-700 → orange-500 → red-600). Hover ô hiện tooltip
  `Txxxx · Tactic — N reports`. Có legend intensity và empty state khi chưa có
  data. Thay thế donut chart MITRE cũ trong `Metrics.tsx`, fetch
  `GET /api/stats/mitre` qua hàm `fetchMitreStats()` mới trong `api.ts`,
  refresh cùng chu kỳ 5s của trang.

**W5 — Flyout drill-down** (commit `db2bbb3`)

- Drawer report detail ở Metrics nâng thành flyout `max-w-2xl`, tab bar sticky
  gồm 3 tab:
  - **Overview**: risk gauge vòng tròn SVG tô màu theo severity, SeverityBadge +
    StatusBadge, timeline xử lý, kết quả Tier-1 pre-filter, executive summary
    (markdown), error logs nếu job Failed.
  - **Evidence**: evidence trail (claim + nguồn), MITRE technique chips dạng
    mono, recommended actions. (Trước W5 các data này API đã trả nhưng UI chưa
    render.)
  - **Raw JSON**: toàn bộ report pretty-printed, font mono 11px, nền slate-950
    — kiểu "xem document thô" của Wazuh.

### Cách hoạt động (luồng data)

```text
Postgres (analysis_jobs, reports.mitre_techniques)
   │  EF Core aggregate / GroupBy
   ▼
GET /api/stats ──────────────┐
GET /api/stats/mitre         ▼
                    frontend/src/services/api.ts (fetch + adapter)
                             ▼
        Metrics.tsx ──► KPI cards, Alerts table, MitreHeatmap, Flyout
```

### Cách kiểm chứng

- Backend: `dotnet test` — 181 unit + 34 integration xanh (3 test mới cho stats).
- Frontend: `npm run build` xanh (1 warning kích thước chunk >500kB của Vite —
  thuần cảnh báo, không phải lỗi; có thể xử lý sau bằng code splitting).
- Tay: chạy full stack, vào trang **Metrics** → bảng Alerts có badge màu,
  sort/filter được; heatmap hiện ô technique; click một dòng alert → flyout 3 tab.

### Phase 2 — Redesign trang chủ SOCDashboard (W7-W8)

Phase 1 chỉ đụng trang Metrics nên trang chủ nhìn "không khác gì". Phase 2
redesign chính SOCDashboard thành layout kiểu OpenSearch Dashboards:

**W7 — Layout mới** (commit `f577953`)

- `frontend/src/services/api.ts` — thêm `fetchStatsApi()` gọi `GET /api/stats`
  (KPI server-side; khác với adapter `fetchStats` cũ tính client-side).
- `frontend/src/pages/SOCDashboard.tsx` — rewrite layout (giữ nguyên logic cũ):
  - **KPI strip** trên cùng: Total Alerts / Critical+High / Avg Risk / Jobs 24h,
    refresh 5s.
  - **Live alert feed làm trung tâm** (grid col-8): danh sách job mới nhất,
    dòng dense (`py-1.5`, `text-xs`): StatusBadge, SeverityBadge, filename mono,
    risk score, time. Auto-refresh 5s. Click dòng → mở flyout.
  - **Cột phải (col-4)**: panel Submit Evidence (upload compact, vẫn drag&drop)
    + Autonomous Agents + SOC Readiness.
  - Pipeline graph và Reasoning Trace chuyển thành **panel collapsible** bên
    dưới — giữ đủ chức năng nhưng xuống vai phụ (SOC thật nhìn alert trước,
    graph sau).
  - Toàn bộ khu vực bọc trong panel viền mảnh (`border-slate-800`), header
    panel uppercase tracking-wide — đúng chất panel grid của OpenSearch.

**W8 — Flyout dùng chung** (commit `8593458`)

- `frontend/src/components/ReportFlyout.tsx` (mới) — tách flyout 3 tab từ
  Metrics.tsx ra component dùng chung; tự fetch detail qua `fetchReportDetail`.
  Thêm 2 state cho job chưa xong: "Pipeline in progress" (hiện `currentStep`)
  và "Pipeline failed" (hiện step + errorMessage).
- Metrics.tsx bỏ ~340 dòng flyout inline, import component chung.
- SOCDashboard: click alert feed → mở cùng ReportFlyout đó.

Layout trang chủ sau redesign:

```text
Header
├─ KPI strip: Total Alerts | Critical+High | Avg Risk | Jobs 24h
├─ Grid 12 cột:
│   ├─ col-8: LIVE ALERT FEED (click row → flyout)
│   └─ col-4: Submit Evidence + Autonomous Agents + SOC Readiness
├─ LIVE AGENT PIPELINE (collapsible)
└─ AUTONOMOUS REASONING TRACE (collapsible)
```

### Ghi chú / Giới hạn

- **Bỏ tính năng click-ô-heatmap-để-filter-bảng**: vì dòng alert lấy từ
  `/api/jobs` không mang technique ID nên filter sẽ không khớp. Muốn làm thì
  backend phải trả kèm techniques trong job summary (việc nhỏ, để sau).
- **IOCs trong flyout đang rỗng**: API report chưa expose danh sách IOC riêng
  (IOC nằm trong DB bảng `iocs` và trong summary). Thêm `iocs[]` vào report DTO
  là việc nhỏ nếu muốn hiển thị.
- Dark theme là hard-code (không có toggle sáng/tối) — cố ý, theo Wazuh.
- Bundle frontend ~500kB — chưa cần tối ưu cho quy mô demo/portfolio.

### Commits

`db0eee2` (W1) · `aab32dd` (W2) · `57e226d` (W3) · `fea07e0` (W4) · `db2bbb3` (W5)
· `89dc48c` (W6 docs) · `f577953` (W7) · `8593458` (W8)

---

## Món 1 — OWASP hardening (hoàn thành)

### Mục tiêu

Đưa API từ "mở toang cho ai cũng gọi được" lên mức baseline theo OWASP:
có authentication (JWT), rate limiting chống spam/brute-force, validate nội
dung file upload thay vì tin extension, security headers trên mọi response, và
CORS siết lại cho production. Đây là phần "nền" — rẻ effort nhưng là chủ đề
phỏng vấn backend kinh điển (OWASP Top 10: A01 Broken Access Control,
A05 Security Misconfiguration, A07 Identification & Authentication Failures).

### Thay đổi chi tiết (commit `4c3aa12`)

**1. JWT auth — login endpoint + bảo vệ toàn bộ API**

- `src/Vigil.Api/Auth/TokenService.cs` (mới) — phát JWT ký HMAC-SHA256.
  Config đọc từ section `Auth`: `Issuer`, `Audience`, `SigningKey` (bắt buộc
  ≥ 32 ký tự, thiếu thì throw ngay lúc boot — fail fast), `TokenLifetimeMinutes`
  (mặc định 720 = 12h). `BuildValidationParameters()` cho middleware validate:
  issuer + audience + signing key + lifetime, clock skew 30s.
- `src/Vigil.Api/Endpoints/AuthEndpoints.cs` (mới) — `POST /api/auth/login`
  nhận `{username, password}`, so với `Auth:AdminUser`/`Auth:AdminPassword`
  trong config, đúng thì trả `{token, expiresInMinutes}`. Endpoint này
  **anonymous** (hiển nhiên) nhưng có rate limit riêng (xem mục 2).
- `JobEndpoints.cs` + `StatsEndpoints.cs` — thêm `.RequireAuthorization()` lên
  cả group `/api/jobs` và `/api/stats`. Chỉ `/health` và `/api/auth/login`
  còn mở.
- Hệ thống single-user (một SOC operator) — credentials nằm trong config, chưa
  cần bảng Users trong DB. Đủ cho quy mô portfolio/demo; multi-user là chuyện
  khác.
- Credential/signing key thật đi vào `appsettings.Development.Local.json`
  (đã gitignore) hoặc biến môi trường `Auth__SigningKey`... — **không bao giờ**
  commit key thật. `appsettings.Development.json` chỉ chứa dev key rõ ràng ghi
  "change-me". Program.cs giờ cũng load thêm file Local (trước chỉ Worker load).

**2. Rate limiting** (`AddRateLimiter` built-in của .NET 9, trong `Program.cs`)

- 2 policy named (`src/Vigil.Api/Security/RateLimitPolicies.cs`):
  - `uploads` → gắn lên `POST /api/jobs`: fixed window **10 req/phút/IP**
    (config `RateLimiting:UploadPermitLimit`).
  - `auth` → gắn lên `POST /api/auth/login`: **5 req/phút/IP** — chống
    brute-force password (config `RateLimiting:AuthPermitLimit`).
- Partition theo `RemoteIpAddress`; vượt limit trả **429 Too Many Requests**
  (`RejectionStatusCode`), không queue (`QueueLimit = 0`).
- **Gotcha đã gặp và sửa:** limit phải đọc từ `IConfiguration` *live* trong
  lambda (qua `httpContext.RequestServices`), không capture lúc startup — vì
  `WebApplicationFactory` của integration test inject config override *sau* khi
  top-level code của `Program.cs` đã chạy, nên giá trị capture sớm sẽ là default
  (5 req/phút) và test bị 429 hàng loạt.

**3. Upload magic-byte validation** (`src/Vigil.Api/Security/UploadFileValidator.cs`, mới)

- Trước đây chỉ check extension (`.eml/.csv/.json`) — đổi tên `malware.exe`
  thành `report.eml` là qua. Giờ sniff 4KB đầu file:
  - Reject signature nguy hiểm: `MZ` (Windows PE), `ELF`, `PK\x03\x04` (zip),
    Mach-O, `%PDF`.
  - Reject file có NUL byte (= binary, không phải text artifact).
  - `.json`: ký tự non-whitespace đầu tiên phải là `{` hoặc `[`.
  - `.eml`: dòng đầu phải có dạng header RFC 822 (`Name: value`).
- Chạy trong `UploadArtifact` sau khi check extension, trước khi ghi đĩa.

**4. Security headers** (middleware trong `Program.cs`, mọi response)

- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`,
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
  (đây là JSON API, browser không cần load resource nào).
- Tắt `Server: Kestrel` header (`ConfigureKestrel(o => o.AddServerHeader = false)`).

**5. CORS siết cho production**

- Dev giữ nguyên: mọi origin localhost (Vite nhảy port 5173→5174).
- Non-dev: chỉ các origin trong `Cors:AllowedOrigins` (config array, mặc định
  rỗng = không cho cross-origin nào).

**6. Frontend login**

- `frontend/src/pages/Login.tsx` (mới) — form login dark theme, gọi
  `POST /api/auth/login`, lưu token vào `localStorage` (`vigil_token`).
- `frontend/src/services/api.ts` — thêm `login/getToken/clearToken/isAuthenticated`
  và wrapper `authFetch`: tự gắn `Authorization: Bearer <token>` vào mọi call;
  gặp 401 → xoá token + redirect `/login`. Tất cả call site (`fetchJobs`,
  `fetchJobReport`, `uploadFile`, `fetchMitreStats`...) chuyển sang `authFetch`.
- `frontend/src/App.tsx` — guard `RequireAuth`: chưa có token thì mọi route
  (trừ `/login`) redirect về `/login`.

**7. Tests**

- `tests/Vigil.IntegrationTests/VigilApiFactory.cs` — inject config test
  (signing key + user/pass test + rate limit nâng lên 100000), thêm helper
  `CreateAuthenticatedClientAsync()`: login thật qua endpoint rồi trả client đã
  gắn Bearer token. Toàn bộ test cũ (9 call site, 6 file) đổi sang helper này.
- `tests/Vigil.IntegrationTests/ApiSecurityTests.cs` (mới, 8 test):
  anonymous bị 401 trên 3 endpoint · `/health` vẫn mở · login sai pass → 401 ·
  login đúng → gọi được `/api/stats` · upload file nội dung MZ → 400 ·
  upload `.json` nội dung không phải JSON → 400 · security headers hiện diện.

### Cách hoạt động (luồng một request)

```
browser → (chưa login) → /login → POST /api/auth/login [rate limit 5/phút]
        → đúng pass → JWT (12h) lưu localStorage
browser → GET /api/jobs + header Authorization: Bearer <jwt>
        → rate limiter (nếu là POST upload) → JWT middleware validate chữ ký
        + hạn → endpoint chạy → response kèm security headers
Token hết hạn/sai → 401 → frontend tự xoá token + về /login
```

### Cách kiểm chứng

- `dotnet test tests/Vigil.UnitTests -c Release` → 181 xanh.
- `dotnet test tests/Vigil.IntegrationTests -c Release` → 42/43 xanh; test
  `Upload_eml_accepts_persists_and_queues_job` fail **vì lý do môi trường**:
  Worker thật đang chạy ngoài sẽ consume message test trong queue `vigil.jobs`
  (bản thân comment trong test đã ghi "the Worker is not running here"). Tắt
  Worker rồi chạy lại là xanh. Không liên quan thay đổi của món này.
- `cd frontend && npm run build` → xanh. (3 eslint error `no-explicit-any`
  trong `api.ts` là có sẵn từ trước, không phải của món này.)
- Test tay: `curl -X POST localhost:5027/api/auth/login -H 'Content-Type: application/json'
  -d '{"username":"admin","password":"vigil-dev"}'` → lấy token; gọi
  `/api/jobs` không token → 401, có token → 200.

### Ghi chú / Giới hạn

- **Single-user**: chưa có bảng Users, đổi password = sửa config + restart API.
- JWT không có refresh token / revoke list — token 12h tự hết hạn. Muốn revoke
  ngay thì đổi `Auth:SigningKey` (mọi token cũ chết).
- Rate limit là in-memory per-instance: scale nhiều instance API thì limit không
  chia sẻ (cần Redis/backplane — chưa làm).
- Magic-byte check chặn executable giả mạo, nhưng không phải antivirus — file
  text độc hại (vd CSV có công thức macro) vẫn qua; pipeline xử lý file là
  read-only nên rủi ro thấp.
- `Content-Security-Policy: default-src 'none'` áp cho API; frontend là app
  riêng (Vite serve) nên không bị ảnh hưởng.

### Commits

`4c3aa12` — toàn bộ món 1 (backend + frontend + tests)

## Món 3 — Sigma rule pack cho Tier 1 (hoàn thành)

### Mục tiêu

Tier 1 trước đây chỉ có rule hard-code trong C# (high-risk API list, recon
burst, z-score...). Món này thêm khả năng **nạp detection rule từ file YAML
chuẩn Sigma** (format rule cộng đồng của SigmaHQ, dùng chung trong ngành SOC):
thêm rule mới = thêm 1 file .yml, không cần sửa code/rebuild logic. Kèm rule
pack CloudTrail viết theo mẫu SigmaHQ. Đây là điểm "chiều sâu detection" để kể
trong phỏng vấn: hiểu Sigma là gì, tại sao rule-as-code, và trade-off khi tự
viết engine mini thay vì kéo nguyên sigma-cli về.

### Thay đổi chi tiết (commit `4fbf043`)

**1. Mini Sigma engine** — `src/Vigil.Core/Tier1/Sigma/` (5 file mới)

- `SigmaYamlParser.cs` — parse YAML bằng YamlDotNet (package mới, 16.3.0).
  Hỗ trợ subset: `title/id/level/description` + `detection` với map selection
  (`field: value`, `field: [list]` = OR, `field|modifier: value`) và
  `condition`. Shape không hỗ trợ (keywords selection, aggregation `count()`
  near...) → throw `FormatException` để loader skip file và ghi lỗi, không bao
  giờ làm sập detection vì 1 rule hỏng.
- `SigmaConditionExpression.cs` — mini-language cho `condition`: `and`/`or`/
  `not`/ngoặc + `1 of them`, `1 of pattern*`, `all of ...`. Tokenize → parse
  recursive-descent thành AST → `1 of pattern*` được expand thành Or-chain các
  selection cụ thể ngay lúc load (validate luôn condition có tham chiếu
  selection không tồn tại → reject rule).
- `SigmaRule.cs` — model: `SigmaRule` (có `Slug` từ title, vd
  "AWS Root Account Usage" → `aws_root_account_usage`), `SigmaSelection`
  (các tiêu chí AND), `SigmaFieldMatcher` (values OR; modifier
  exact/contains/startswith/endswith; wildcard `*`/`?` case-insensitive bằng
  glob matcher tự viết — 2 con trỏ + backtrack).
- `SigmaFieldNormalizer.cs` — **mấu chốt kết nối**: rule SigmaHQ viết cho
  CloudTrail JSON (`userIdentity.userName`), còn CSV của mình flatten
  (`userIdentityuserName`). Normalize cả hai về cùng dạng (lowercase, bỏ mọi
  ký tự không phải chữ/số) nên khớp nhau.
- `SigmaEngine.cs` — `LoadFromDirectory()` đọc đệ quy `*.yml`/`*.yaml`;
  `Evaluate(event)` trả các rule match (kết quả selection được cache per-rule
  per-event); `EvaluateBatch()` gom distinct rule + số hit cho cả file log.
  `SigmaEngine.Default` (lazy singleton) nạp từ `$VIGIL_RULES_DIR` hoặc
  `<thư mục chạy>/rules`; không có thư mục → engine rỗng, no-op sạch.
  `LoadErrors` expose các file rule parse hỏng.

**2. Nối vào pipeline Tier 1**

- `CsvLogParser.cs` — mỗi `CsvLogRecord` giờ mang thêm `Fields`: dictionary
  **toàn bộ cột** của dòng (key = header đã normalize). Trước đây parser bỏ
  mọi cột không nằm trong alias map, Sigma sẽ không có gì để match.
- `CsvLogRuleChecks.Analyze(csv, engine?)` — overload mới, tham số engine
  optional (null → `SigmaEngine.Default`). Check thứ 6 `sigma_rules`: rule
  match → `MatchedRules` thêm `sigma:<slug>` (đúng convention evidence trail),
  `Extracted["sigmaRulesLoaded"]` ghi số rule đã nạp, `RuleCheck.Detail` liệt
  kê "Title [level] × hits". Sigma nằm chung hệ "family" khi tính RiskScore
  (mỗi family +15, cap 100) và tự kế thừa verdict policy sẵn có: 1 rule match
  → Suspicious.
- `src/Vigil.Worker/Vigil.Worker.csproj` — copy `rules/**` vào output
  (`<output>/rules`) để `SigmaEngine.Default` thấy khi Worker chạy.

**3. Rule pack** — `rules/cloudtrail/` (9 rule, viết theo mẫu SigmaHQ)

| Rule | Level | Phát hiện |
|---|---|---|
| aws_console_login_without_mfa | high | ConsoleLogin không có `MFAUsed: Yes` |
| aws_root_account_usage | critical | `userIdentity.type: Root` (trừ call bị error) |
| aws_cloudtrail_logging_tampered | critical | StopLogging/DeleteTrail/UpdateTrail/PutEventSelectors |
| aws_security_group_open_to_world | high | AuthorizeSecurityGroupIngress với 0.0.0.0/0 hoặc ::/0 |
| aws_iam_backdoor_access_key | medium | CreateAccessKey (persistence) |
| aws_iam_privilege_escalation_policy | high | Attach*/Put*Policy, CreatePolicyVersion... |
| aws_config_recording_disabled | high | Tắt/xoá AWS Config recorder |
| aws_guardduty_disruption | critical | Xoá/tắt GuardDuty detector, threat intel set |
| aws_sts_assume_role | medium | AssumeRole/SAML/WebIdentity (pivot) |

Lưu ý: rule nào tham chiếu field CSV không có (vd `additionalEventData.MFAUsed`)
thì đơn giản không match — missing field = không match, không lỗi. Pack match
tốt nhất với CSV export đủ cột CloudTrail.

### Cách hoạt động

```
rules/cloudtrail/*.yml ──(copy vào output khi build Worker)──► <bin>/rules
        │
Worker start → SigmaEngine.Default lazy-load 1 lần (parse YAML → AST, validate)
        │
Job CSV → CsvLogParser (mỗi dòng → Fields dict) → 5 check hard-code như cũ
        → check 6: EvaluateBatch(Fields) → rule match → sigma:<slug> vào
          MatchedRules → jsonb tier1_results → Tier 2 đọc evidence như thường
```

### Cách kiểm chứng

- 13 unit test mới (`tests/Vigil.UnitTests/Tier1/Sigma/`): exact/list-OR/
  contains/wildcard, `and not`, `1 of pattern*`, missing field không match,
  field dotted↔flattened, rule hỏng vào `LoadErrors` chứ không throw, condition
  tham chiếu selection ma bị reject, `EvaluateBatch` đếm hit, **shipped pack
  load sạch 0 lỗi và đủ ≥ 8 rule**, tích hợp `CsvLogRuleChecks` (match →
  `sigma:` + Suspicious; engine rỗng → no-op; loaded nhưng không match → pass).
- `dotnet test tests/Vigil.UnitTests -c Release` → 194 xanh (181 cũ + 13 mới).
- Integration 42/43 như cũ (1 fail môi trường đã ghi ở Món 1 — Worker đang
  chạy ngoài ăn message test).
- Kiểm tay: `src/Vigil.Worker/bin/Release/net9.0/rules/cloudtrail/` có đủ
  9 file .yml sau build.

### Ghi chú / Giới hạn

- Subset Sigma, **không phải** full spec: chưa có keywords selection,
  aggregation (`count() by user > 5` near...), correlation, `|re` regex,
  value modifiers nâng cao (`|cidr`, `|base64`). Rule SigmaHQ xịn copy thẳng
  về có thể parse fail → rơi vào `LoadErrors`, cần lược bớt cho hợp subset.
- `all of pattern*` với 0 selection khớp → false (hiện thực chọn vậy; Sigma
  spec mập mờ chỗ này).
- Rules load 1 lần lúc Worker khởi động (lazy static) — sửa file .yml phải
  restart Worker. Chưa có hot-reload.
- Rule chỉ chạy cho artifact CSV (CloudTrail-style). Email (.eml) có hệ rule
  riêng (`EmailRuleChecks`), chưa đưa Sigma vào — Sigma vốn cho log/event,
  không hợp email lắm.
- Thêm rule mới: thả file .yml vào `rules/cloudtrail/` (hoặc subdir khác),
  rebuild để copy, restart Worker.

### Commits

`4fbf043` — engine + parser wiring + 9 rules + tests
