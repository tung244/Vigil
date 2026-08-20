# Vigil — Nhật ký nâng cấp (UPGRADES)

> File này ghi lại **chi tiết** các đợt nâng cấp sau v1, để khi quay lại project sau
> một thờian gian vẫn đọc và hiểu được: đợt đó làm gì, tại sao làm, hoạt động ra
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

---

## Món 1 — OWASP hardening (chưa làm)

Kế hoạch: JWT auth cho API, rate limiting (upload + read), upload validation
theo magic bytes, security headers, siết CORS cho production.
*(Sẽ viết chi tiết vào mục này khi hoàn thành.)*

## Món 3 — Sigma rule pack cho Tier 1 (chưa làm)

Kế hoạch: Sigma-compatible rule engine mini (parse YAML rule → match event),
rule pack CloudTrail từ SigmaHQ nạp runtime vào thư mục `rules/`, matched rule
ghi vào evidence trail dạng `rule:sigma:<tên-rule>`.
*(Sẽ viết chi tiết vào mục này khi hoàn thành.)*
