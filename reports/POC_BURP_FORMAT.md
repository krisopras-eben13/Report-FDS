# PoC — Format Burp Suite Repeater
## FDS Bank Sulut Go — Observasi Teknis dan Pengujian Authorization

**Target:** `https://fds-dev-sites.skyworx.co.id`  
**Deployment yang diuji:** `6be8fb3` (sesi awal), `54ac33f` (deployment terkini)  
**Tujuan:** Memberikan request HTTP mentah yang dapat direproduksi untuk verifikasi perilaku authorization dan Server Action.

> **PERINGATAN**: Dokumen ini BUKAN daftar exploit yang terkonfirmasi. Beberapa request di bawah ini telah **ditutup sebagai expected behavior** atau **false positive** setelah klarifikasi developer dan analisis teknis lebih lanjut. Gunakan hanya untuk memverifikasi ulang perilaku authorization sesuai policy yang telah ditetapkan, bukan untuk mengklaim kerentanan tanpa konfirmasi ulang.

---

## STEP 0 — Login (Memperoleh Session Token)

Login menggunakan `tools/login.py` atau secara manual melalui form.

### Request Login Checker

```http
POST /login HTTP/2
Host: fds-dev-sites.skyworx.co.id
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/x-component
Accept-Language: en-US,en;q=0.5
Referer: https://fds-dev-sites.skyworx.co.id/login
Next-Action: 780cd88624239ff089c50c69bcd7cd79a51c2d1fc6
Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22login%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%2C0%5D%7D%2Cnull%2Cnull%2C0%5D%7D%2Cnull%2Cnull%2C16%5D
X-Deployment-Id: 54ac33f
Content-Type: multipart/form-data; boundary=----geckoformboundary[RANDOM]
Origin: https://fds-dev-sites.skyworx.co.id

------geckoformboundary[RANDOM]
Content-Disposition: form-data; name="_1_password"

[AES-256-GCM envelope — lihat tools/login.py untuk pembangkitan otomatis]
------geckoformboundary[RANDOM]
Content-Disposition: form-data; name="_1_email"

endangchecker@gmail.com
------geckoformboundary[RANDOM]
Content-Disposition: form-data; name="0"

["$K1","[KEY_HEX]","370aa00142210fd41d76e0188ad0540b","/dashboard"]
------geckoformboundary[RANDOM]--
```

> **Catatan:** Field `_1_password` adalah envelope AES-256-GCM yang dibuat fresh setiap kali dengan key acak. Script `tools/login.py` mengotomasi proses ini dan menangani single-device enforcement.

### Expected Response — Login Berhasil

```http
HTTP/2 200 OK
set-cookie: session=eyJhbGciOiJIUzI1NiJ9...; Path=/; Secure; HttpOnly; SameSite=lax
set-cookie: refresh_token=eyJhbGciOiJIUzI1NiJ9...; Path=/; Secure; HttpOnly; SameSite=lax
x-action-redirect: /dashboard;push
```

**Ekstrak nilai `session=...` dari Set-Cookie.**  
Ini adalah `<SESSION_CHECKER>` atau `<SESSION_APPROVER>` yang digunakan di semua request berikut.

---

## OBSERVASI 1 — getCaseNotes dengan Case ID Berbeda

**Status:** **DITUTUP** — Developer mengonfirmasi bahwa semua user dengan permission `view_cases` dapat membaca semua case dan notes. Behavior ini adalah design, bukan IDOR.

**Deployment:** `6be8fb3` (action ID lama)

### Request

```http
POST /case-management/cases/b87acde7-9b47-42d8-8980-4d6464c4f76b HTTP/2
Host: fds-dev-sites.skyworx.co.id
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/x-component
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://fds-dev-sites.skyworx.co.id/case-management/cases/b87acde7-9b47-42d8-8980-4d6464c4f76b
Next-Action: 40ef5335bbdeb78d3c69ee038367140977ff4d2797
X-Deployment-Id: 6be8fb3
Content-Type: text/plain;charset=UTF-8
Content-Length: 75
Origin: https://fds-dev-sites.skyworx.co.id
Cookie: session=<SESSION_APPROVER>

[{"caseId":"aafc67a4-d2bc-4264-8bf9-065b7fe8816c","page":1,"limit":20}]
```

> **Perhatikan:** URL path berisi case `b87acde7`, tetapi **body `caseId`** mengarah ke `aafc67a4`.  
> **Interpretasi lama yang salah:** "attacker dapat membaca case milik orang lain."  
> **Interpretasi yang benar:** Backend menggunakan body `caseId` sebagai target; tidak ada validasi bahwa path dan body cocok; developer mengonfirmasi semua user boleh lihat semua case, sehingga ini bukan unauthorized access.

### Response — Data Notes Dikembalikan

```http
HTTP/2 200 OK
Content-Type: text/x-component

0:{"a":"$@1","q":"","i":false}
1:{
  "data": [
    {
      "id": "01a0c1d6-7d90-7605-8239-028877eba074",
      "authorName": "udinmovic",
      "body": "saya rekomendasikan case ini menjadi approved"
    },
    {
      "id": "01a0c1d9-cd99-7ae6-a6e4-271b3423ff84",
      "authorName": "bili",
      "body": "oke noted pak"
    }
  ],
  "pagination": {"page":1,"limit":20,"total":5,"totalPages":1}
}
```

**Tidak ada bukti:** case `aafc67a4` "tidak boleh" diakses oleh user ini. Evidence yang dikirim sebelumnya menunjukkan akun test (`endangapprover@gmail.com`) pernah menulis notes `"test"` dan `"[[marker]]"` ke case tersebut, artinya case ini accessible oleh akun itu sesuai desain.

---

## OBSERVASI 2 — addCaseNote dengan Case ID Berbeda

**Status:** **DITUTUP** — Developer mengonfirmasi bahwa semua user dengan permission `update_cases` dapat menulis notes pada case manapun.

**Deployment:** `6be8fb3`

### Request

```http
POST /case-management/cases/b87acde7-9b47-42d8-8980-4d6464c4f76b HTTP/2
Host: fds-dev-sites.skyworx.co.id
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/x-component
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://fds-dev-sites.skyworx.co.id/case-management/cases/b87acde7-9b47-42d8-8980-4d6464c4f76b
Next-Action: 4099805213576e22934a4121eb3231dfb996dfd39e
X-Deployment-Id: 6be8fb3
Content-Type: text/plain;charset=UTF-8
Content-Length: 115
Origin: https://fds-dev-sites.skyworx.co.id
Cookie: session=<SESSION_APPROVER>

[{"caseId":"aafc67a4-d2bc-4264-8bf9-065b7fe8816c","body":"[PENTEST-MARKER-CROSS-CASE]"}]
```

### Response — Note Dibuat

```http
HTTP/2 200 OK

0:{"a":"$@1","q":"","i":false}
1:{
  "data": {
    "id": "01a1c255-1d5b-7a00-a327-f67c3609c6c9",
    "authorId": "01a1aef9-bbcf-7787-93bb-7a3fc610a4e4",
    "authorName": "Endang Nurakhiri Approver",
    "body": "[PENTEST-MARKER-CROSS-CASE]",
    "createdAt": "$D2026-11-09T21:59:xx.xxxZ"
  }
}
```

**Catatan penting untuk developer:** Note dengan marker uji `[PENTEST-MARKER-CROSS-CASE]` (ID `01a1c255-1d5b-7a00-a327-f67c3609c6c9`) tersimpan di database dan perlu dibersihkan sesuai prosedur data lab.

**Tidak ada bukti:** note ini "tidak seharusnya" bisa dibuat oleh user ini. Design saat ini mengizinkan semua user menulis notes pada case manapun.

---

## OBSERVASI 3 — Akses Konfigurasi Sistem: Checker vs Approver

**Status:** **PENDING BUSINESS CONFIRMATION** — Asymmetry terkonfirmasi secara teknis; perlu dikonfirmasi apakah ini intentional design atau misconfiguration permission.

**Deployment:** `6be8fb3` untuk data di bawah; `54ac33f` untuk action ID terbaru

### Request — Checker Mengakses Konfigurasi

```http
POST /case-management/cases/b87acde7-9b47-42d8-8980-4d6464c4f76b HTTP/2
Host: fds-dev-sites.skyworx.co.id
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/x-component
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://fds-dev-sites.skyworx.co.id/case-management/cases/b87acde7-9b47-42d8-8980-4d6464c4f76b
Next-Action: 00dddc25f8d7106fd043c96052f056e3542e4068c3
X-Deployment-Id: 6be8fb3
Content-Type: text/plain;charset=UTF-8
Content-Length: 2
Origin: https://fds-dev-sites.skyworx.co.id
Cookie: session=<SESSION_CHECKER>

[]
```

### Response — Checker Mendapat Data Konfigurasi

```http
HTTP/2 200 OK

0:{"a":"$@1","q":"","i":false}
1:{
  "data": {
    "riskScore": {
      "maxScore": 100,
      "medium": { "max_score": 79 },
      "high": { "min_score": 80 }
    },
    "autoResolve": {
      "medium": { "is_active": false, "timeout": { "time": 30, "time_type": "minutes" } },
      "high": { "is_active": true, "timeout": { "time": 30, "time_type": "hours" } }
    },
    "overdue": {
      "medium": { "is_active": false, "timeout": { "time": 15, "time_type": "minutes" } },
      "high": { "is_active": true, "timeout": { "time": 15, "time_type": "minutes" } }
    }
  }
}
```

### Request — Approver Mengakses Endpoint yang Sama

```http
POST /case-management/cases/b87acde7-9b47-42d8-8980-4d6464c4f76b HTTP/2
Host: fds-dev-sites.skyworx.co.id
Next-Action: 00dddc25f8d7106fd043c96052f056e3542e4068c3
X-Deployment-Id: 6be8fb3
Content-Type: text/plain;charset=UTF-8
Cookie: session=<SESSION_APPROVER>

[]
```

### Response — Approver Mendapat 403

```http
HTTP/2 200 OK

0:{"a":"$@1","q":"","i":false}
1:{"data":null,"error":{"code":403,"message":"Forbidden"}}
```

> **Note teknis:** HTTP wrapper adalah 200 karena Next.js Server Actions selalu mengembalikan 200; error authorization ada di **body response** dalam format RSC.

### JWT Checker Memuat Permission `view_case_configuration`

Berdasarkan JWT payload yang dibagikan:

```json
{
  "permissions": [
    "view_case_configuration",
    "view_rule_configuration",
    "view_cases",
    "update_cases",
    ...
  ]
}
```

Checker **secara eksplisit memiliki** permission `view_case_configuration`. Jika action ini memeriksa permission tersebut dan Checker memang diberi permission itu pada role definition, maka behavior ini **bukan bypass authorization** — ini adalah **correctly enforced authorization based on assigned permission**.

**Pertanyaan untuk developer/stakeholder:**  
Apakah permission `view_case_configuration` memang dimaksudkan untuk diberikan kepada role Checker, dan apakah konfigurasi `riskScore`, `autoResolve`, `overdue` memang boleh diakses oleh role operasional?

**Action ID pada deployment terbaru (`54ac33f`):** `00b334e04aad3e9a35d56a2d991b350927f0c21de8`

---

## OBSERVASI 4 — Action `refreshSessionAction`

**Status:** **DITUTUP — FALSE POSITIVE** — Bundle analysis mengidentifikasi action ini sebagai `refreshSessionAction` yang memperbarui idle timer, bukan action workflow case.

**Deployment:** `6be8fb3` (action ID lama)

### Request

```http
POST /case-management/cases/b87acde7-9b47-42d8-8980-4d6464c4f76b HTTP/2
Host: fds-dev-sites.skyworx.co.id
Next-Action: 00e132e5a1d7f51d9b33ff7a0809369fc481bfc23a
X-Deployment-Id: 6be8fb3
Content-Type: text/plain;charset=UTF-8
Cookie: session=<SESSION_CHECKER>

[]
```

### Response — Success True

```http
HTTP/2 200 OK

0:{"a":"$@1","q":"","i":false}
1:{"success":true}
```

### Bundle Evidence

Dari `recon/case_js/20mkfmidwco7f.js`:

```javascript
createServerReference(
  "00e132e5a1d7f51d9b33ff7a0809369fc481bfc23a",
  callServer, void 0, findSourceMapURL,
  "refreshSessionAction"
)
```

Action ini adalah session idle timer refresh. Tidak ada perubahan data case, status, decision, atau note count yang teramati sebelum dan sesudah pemanggilan action ini.

**Action ID pada deployment `54ac33f`:** `00e2c30fb1fde7b1cb22bf9faef4a28eeeb03019fe` (kandidat berdasarkan response pattern; nama belum dikonfirmasi dari bundle baru)

---

## Pengujian CSRF — Origin Validation

**Status:** **CSRF via browser NOT EXPLOITABLE** — Next.js Server Actions enforce Origin comparison; external dan null origins ditolak.

### Test Matrix

| Origin Header | getCaseNotes Response | Config Action Response |
|---|---|---|
| `https://fds-dev-sites.skyworx.co.id` (same-origin) | 200 + data | 200 + data/403 based on role |
| `https://evil-csrf-test.example` (external) | 500 (rejection) | 500 (rejection) |
| `null` | 500 (rejection) | 500 (rejection) |
| *(header absent)* | 200 + data | 200 + data/403 |

**Request dengan Origin Eksternal:**

```http
POST /case-management/cases/b87acde7-9b47-42d8-8980-4d6464c4f76b HTTP/2
Host: fds-dev-sites.skyworx.co.id
Next-Action: 40c98d132338e6c0ca57bb92c2aa52aabe235ac724
Content-Type: text/plain;charset=UTF-8
Origin: https://evil-csrf-test.example
Cookie: session=<SESSION_APPROVER>

[{"caseId":"b87acde7-9b47-42d8-8980-4d6464c4f76b","page":1,"limit":20}]
```

**Response:**

```http
HTTP/2 500 Internal Server Error

0:{"a":"$@1","q":"","i":false}
1:E{"digest":"2514581661"}
```

Next.js internal error saat Origin tidak cocok. **Ini adalah rejection, bukan bypass.**

**Cookie flags:** `SameSite=Lax` + Next.js Origin validation = defense-in-depth terhadap CSRF.

---

## Pengujian Next.js Specific Surface

### CVE-2025-29927 — Middleware Subrequest Header

**Status:** NOT VULNERABLE

```http
GET /dashboard HTTP/2
Host: fds-dev-sites.skyworx.co.id
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware

→ HTTP/2 307 Temporary Redirect
→ Location: /login
```

Middleware authentication tetap enforced.

### /_next/image SSRF

**Status:** NOT VULNERABLE — Allowlist aktif

```http
GET /_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75 HTTP/2
Host: fds-dev-sites.skyworx.co.id

→ HTTP/2 400 Bad Request
→ "url" parameter is not allowed
```

`images.remotePatterns` / `images.domains` allowlist aktif; URL metadata atau arbitrary external URLs ditolak.

---

## Verification Commands

Untuk mereproduksi observasi di atas, login terlebih dahulu:

```bash
# Login checker
python3 -I tools/login.py endangchecker@gmail.com 'IndonesiaJaya@2026' /tmp/c.txt

# Ekstrak session token
CS=$(grep -oP 'session\t\K\S+' /tmp/c.txt)

# Test getCaseNotes (deployment 54ac33f)
curl -sk 'https://fds-dev-sites.skyworx.co.id/case-management/cases/b87acde7-9b47-42d8-8980-4d6464c4f76b' \
  -b "session=$CS" \
  -H 'Next-Action: 40c98d132338e6c0ca57bb92c2aa52aabe235ac724' \
  -H 'Content-Type: text/plain;charset=UTF-8' \
  -H 'X-Deployment-Id: 54ac33f' \
  -d '[{"caseId":"b87acde7-9b47-42d8-8980-4d6464c4f76b","page":1,"limit":20}]'

# Test config action (deployment 54ac33f)
curl -sk 'https://fds-dev-sites.skyworx.co.id/case-management/cases/b87acde7-9b47-42d8-8980-4d6464c4f76b' \
  -b "session=$CS" \
  -H 'Next-Action: 00b334e04aad3e9a35d56a2d991b350927f0c21de8' \
  -H 'Content-Type: text/plain;charset=UTF-8' \
  -H 'X-Deployment-Id: 54ac33f' \
  -d '[]'
```

---

## Catatan Deployment dan Action ID

| Deployment | Login Action | getCaseNotes | Config | Refresh |
|---|---|---|---|---|
| `6be8fb3` | `78af4e5c...` | `40ef5335...` | `00dddc25...` | `00e132e5...` |
| `54ac33f` | `780cd886...` | `40c98d13...` | `00b334e0...` | `00e2c30f...` |

Action ID berubah setiap deployment. Jangan memakai action ID lama untuk testing deployment baru.

---

## Kesimpulan untuk Atasan

1. **Tidak ada 4 temuan High yang terkonfirmasi.** FDS-011 dan FDS-012 adalah expected behavior sesuai design access control saat ini. FDS-014 adalah `refreshSessionAction` yang tidak mengubah state case.

2. **FDS-013 memerlukan keputusan policy.** Asymmetry terkonfirmasi secara teknis; Checker memiliki permission `view_case_configuration` di JWT; perlu dikonfirmasi apakah ini intentional atau misconfiguration.

3. **CSRF tidak exploitable via browser.** Next.js Server Actions enforce Origin validation; external origins ditolak dengan HTTP 500.

4. **Next.js CVEs tested (CVE-2025-29927, image SSRF) tidak applicable.** Middleware dan image allowlist bekerja dengan benar.

5. **Marker testing tersisa di database** dan perlu dibersihkan: note ID `01a1c255-1d5b-7a00-a327-f67c3609c6c9` dengan body `[PENTEST-MARKER-CROSS-CASE]`.

---

*PoC ini dibuat untuk authorized penetration testing pada lab environment.*  
*Semua request dieksekusi menggunakan akun yang diberikan untuk tujuan pengujian.*  
*Redaksi session token dan password diperlukan sebelum laporan dibagikan.*
