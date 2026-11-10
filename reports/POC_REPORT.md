# FDS — Laporan Bukti dan Reassessment PoC

**Target:** `https://fds-dev-sites.skyworx.co.id` (development)  
**Periode observasi:** 9–10 November 2026  
**Akun uji:** Checker dan Approver yang diberikan untuk pengujian  
**Rujukan:** `loot/PENTEST_REPORT.md`, `loot/poc_evidence.json`, `recon/case_js/`  
**Klasifikasi:** Internal — redaksi cookie, password, dan data nasabah sebelum distribusi.

> **Koreksi terhadap versi sebelumnya:** Tidak ada empat temuan High yang terkonfirmasi. Dua dugaan IDOR sesuai desain akses saat ini; satu action adalah refresh session; akses konfigurasi berbeda antar-role tetapi izin Checker tercantum di JWT dan maksud bisnisnya masih perlu dikonfirmasi. CVSS tidak ditetapkan untuk perilaku yang bukan kerentanan atau belum terbukti melanggar aturan akses.

## Ringkasan, diurutkan dari informational

| ID | Observasi | Status | Dampak terbukti | CVSS |
|---|---|---|---|---|
| FDS-004 | Rotasi refresh token belum diuji tuntas | Belum diverifikasi | Tidak ada | N/A |
| FDS-005 | Tidak ada token CSRF eksplisit | Bukan bukti celah; Origin eksternal/null ditolak pada action baca | Tidak ada | N/A |
| FDS-006 | Header mengungkap Next.js/deployment | Hardening opsional | Fingerprinting | Belum ditetapkan |
| FDS-008 | Teks HTML-like tersimpan sebagai note | React renderer menampilkan sebagai teks; XSS belum terbukti | Tidak ada eksekusi | N/A |
| FDS-010 | Password dienkripsi di client dan kunci ikut dikirim | Pertimbangan desain; TLS tetap diperlukan | Tidak ada exploit terbukti | N/A |
| FDS-015 | Alur bisnis tampak dalam bundle lama | Peta uji, bukan celah | Tidak ada | N/A |
| FDS-002 | `/api/health` publik mengembalikan `{"status":"ok"}` | Observasi terkonfirmasi; kebijakan akses belum diketahui | Status layanan saja | Belum ditetapkan |
| FDS-003 | Action tanpa sesi/konteks valid pernah memberi HTTP 500 | Observasi error handling; penyebab spesifik belum dipastikan | Tidak ada bypass | Belum ditetapkan |
| FDS-007 | Lockout muncul setelah kegagalan login | Kontrol aktif; risiko penguncian akun bersifat kondisional | Gangguan login sementara teramati | Belum ditetapkan |
| FDS-009 | dj melaporkan batas payload note besar | Observasi manual; ukuran persis dan lapisan penolak belum diverifikasi | Masalah validasi/UX belum diukur | Belum ditetapkan |
| FDS-001 | CSP berisi `unsafe-inline` dan `unsafe-eval` | Konfigurasi terkonfirmasi, XSS belum ditemukan | Perlindungan CSP lemah | Belum ditetapkan |
| FDS-013 | Checker menerima konfigurasi; Approver mendapat error 403 di body | Asimetri terkonfirmasi pada deploy lama; intent permission belum diketahui | Pengungkapan konfigurasi kepada role yang memilikinya | **Tunda sampai policy dikonfirmasi** |
| FDS-011 | Baca notes case berbeda | **Ditutup — sesuai desain** | Tidak ada akses di luar hak yang ditetapkan developer | N/A |
| FDS-012 | Tulis notes case berbeda | **Ditutup — sesuai desain** | Penulisan yang diizinkan oleh model saat ini | N/A |
| FDS-014 | `success:true` lintas role | **Ditutup — `refreshSessionAction`** | Tidak ada perubahan status case terbukti | N/A |

## Bukti yang benar-benar direproduksi

### FDS-011 dan FDS-012 — perilaku lintas-case, bukan IDOR

Pada deployment `6be8fb3`, request `getCaseNotes` dengan case ID berbeda dari path URL mengembalikan notes untuk case ID yang diminta. `addCaseNote` juga menghasilkan ID note dan note muncul saat dibaca ulang. Contoh marker tersimpan: `[PENTEST-IDOR-CROSS-CASE]`; ID note dari berkas evidence: `01a1c255-1d5b-7a00-a327-f67c3609c6c9`.

**Klarifikasi developer:** semua pengguna berizin dapat membaca semua case dan menulis notes; scoping organisasi belum diterapkan pada tahap development ini. Kecocokan ID path/body mungkin merupakan isu konsistensi API, **bukan** bukti pelanggaran hak akses. PoC tidak boleh menyebut case URL sebagai “milik attacker” atau case lain sebagai “milik victim”: assignment dan organisasi berbeda tidak terbukti. Nilai CVSS lama 7.1/8.1 dicabut. Marker uji yang tersimpan perlu ditinjau dan dibersihkan oleh pemilik data sesuai prosedur.

### FDS-013 — akses konfigurasi berbeda antar-role

Deployment `6be8fb3`, action `00dddc25f8d7106fd043c96052f056e3542e4068c3`:

```text
Checker → HTTP 200; RSC body memuat riskScore, autoResolve, overdue
Approver → HTTP 200; RSC body {"data":null,"error":{"code":403,"message":"Forbidden"}}
```

Deployment `54ac33f`: action baru `00b334e04aad3e9a35d56a2d991b350927f0c21de8` tercatat memberi `403` di body pada Approver; perbandingan Checker pada deploy baru belum berhasil diverifikasi. JWT Checker yang dibagikan dj secara eksplisit memuat `view_case_configuration`; hasil lama **konsisten dengan pemeriksaan permission**, bukan bukti bypass. Developer perlu menjawab apakah permission tersebut memang sengaja diberikan untuk membaca konfigurasi itu. Tidak ada bukti bahwa nilai threshold dev dipakai di produksi atau bahwa mengetahui nilainya cukup untuk mengendalikan skor transaksi.

**CVSS/CIA:** confidentiality mungkin relevan *hanya bila* policy melarang Checker membaca data ini; integrity dan availability tidak terbukti terdampak. Jangan menetapkan skor numerik sebelum keputusan policy dan sensitivitas konfigurasi diperoleh.

### FDS-014 — dugaan action workflow ditutup

`recon/case_js/20mkfmidwco7f.js` memetakan action lama `00e132e5a1d7f51d9b33ff7a0809369fc481bfc23a` ke **`refreshSessionAction`**, yang mengembalikan `{"success":true}` untuk sesi berizin. Kandidat pengganti pada deployment baru: `00e2c30fb1fde7b1cb22bf9faef4a28eeeb03019fe` berdasarkan pola respons; pemetaan nama di bundle baru perlu konfirmasi. Tidak ada perubahan count notes sebelum/sesudah panggilan. Perubahan state case tidak diukur menyeluruh, sehingga jangan menyimpulkan aksi ini melakukan approval, override, atau bypass workflow. Skor CVSS 8.1 lama dicabut.

### FDS-001, FDS-008, FDS-009 — input dan output

Header CSP pada target mengizinkan `script-src 'unsafe-inline' 'unsafe-eval'`; ini kelemahan defense-in-depth, bukan XSS yang terbukti. Payload note `<img src=x onerror=alert(1)>` diterima dan dikembalikan sebagai string; bundle note merender `children:e.body`, bukan `innerHTML`. Verifikasi DOM headless gagal karena driver browser tidak tersedia. Klaim batas note sebelumnya tidak stabil: dj menyebut pengujian payload `AAA` sekitar **100–500 MB** dengan penolakan di atas kisaran **400 MB**; versi laporan lama menulis **400 bytes** tanpa bukti. Ukuran persis, status respons, dan lokasi penolakan **belum dibuktikan**. Jangan ulangi uji payload besar/DoS tanpa prosedur terpisah.

## Hasil uji negatif dan keterbatasan

- JWT `alg:none` dan pengubahan role ditolak pada pengujian sebelumnya; tidak membuktikan semua isu session aman.
- Header `x-middleware-subrequest` tidak mengubah redirect `307 /login` tanpa autentikasi.
- `/_next/image` menolak URL metadata dengan `400`, bukan bukti SSRF.
- Origin eksternal dan `null` ditolak pada Server Action baca (HTTP 500 dengan digest); Origin hilang diterima oleh HTTP client, tetapi tidak membuktikan CSRF lintas-browser. State-changing CSRF belum diuji lewat browser.
- Header forwarding dan path berakhiran `.css/.js` tidak mengubah redirect unauthenticated; cache response terautentikasi, respons lintas pengguna, dan cache key belum diverifikasi. Tidak ada cache poisoning yang terkonfirmasi.
- Sepuluh request pembuatan note paralel menghasilkan sepuluh ID unik; **bukan** bukti bahwa workflow approval tahan race condition. Tes itu meninggalkan note marker uji.
- Bundle lama menampilkan UI `OPEN → REVIEW → REQUEST_APPROVE → RESOLVED` dengan pilihan `APPROVE` dan `BLOCK`; pengamanan transisi di backend belum diuji.
- ID Server Action berubah antar-deployment. Jangan replay ID lama pada deployment baru dan menafsirkan `Server Action unavailable` sebagai hasil otorisasi.

## Tindak lanjut yang dapat dipertanggungjawabkan

1. Minta developer menetapkan matrix permission konfigurasi dan sensitivitasnya; tutup atau buka FDS-013 sesuai jawaban.
2. Untuk CSRF, verifikasi **operasi yang memang mengubah state** melalui browser berbeda origin, dengan akun dan record uji; rekam cookie yang dikirim dan perbedaan state. Uji action baca saja tidak cukup.
3. Untuk cache, periksa `Cache-Control`, `Vary`, `Age`, dan cache key pada response autentikasi dengan dua akun uji; jangan menyimpulkan poisoning hanya dari satu respons berubah.
4. Lakukan pengujian self-approval, lompatan status, dan double approval hanya pada case uji serta dengan prosedur yang memungkinkan pemulihan state.
5. Catat ukuran payload note secara **tepat** dari request/response tersimpan tanpa mengulang beban ratusan MB.
6. Perbaiki laporan hanya setelah pembuktian dampak; CVSS dihitung untuk vulnerability yang telah diverifikasi, bukan untuk kemampuan yang memang merupakan desain.

## Penanganan evidence

`loot/poc_evidence.json` adalah rekaman respons lama, **bukan daftar temuan yang masih valid**. Semua cookie/session dan password harus diredaksi sebelum laporan dibagikan. Jangan melampirkan berkas session asli. Tidak ada CVSS gabungan atau attack chain yang terbukti dari temuan yang telah ditutup.
