# MacGuard

Alat pemindai anomali dan remediasi untuk macOS. Memeriksa aplikasi, mekanisme
persistence, proses yang berjalan, dan aktivitas jaringan, lalu memungkinkan Anda
memkarantina apa pun yang mencurigakan alih-alih menghapusnya.

Semuanya bisa dibalik sampai Anda menjalankan `purge`.

## Kebutuhan

- macOS 13 (Ventura) atau lebih baru
- Swift toolchain (Xcode CLT sudah cukup)
- Tanpa dependensi pihak ketiga — hanya CryptoKit dan Foundation

## Build

```bash
cd /Users/fajarpratama/test-mac
swift build -c release
```

Binary ada di `.build/release/macguard`. Untuk pengembangan lokal pakai
`swift build` dan `.build/debug/macguard`.

Agar bisa dipanggil tanpa path lengkap:

```bash
sudo ln -sf "$PWD/.build/release/macguard" /usr/local/bin/macguard
```

## Test

```bash
swift test
```

69 test di 11 suite (termasuk 5 smoke test). Mencakup path traversal, sanitasi
environment subprocess, penandatanganan HMAC record, deteksi manipulasi,
verifikasi dan rotasi rantai audit, pemisahan hak akses root/user, serta
pousan ulang diri scanner (self-exclusion) dan pembacaan bit hardened runtime.

## Mulai Cepat

```bash
# Lihat kondisinya. Tidak menulis, tidak butuh root.
macguard scan

# Periksa satu file atau app bundle. Read-only.
macguard inspect /Applications/SomeApp.app

# Keluarkan item persistence dari disk. Butuh root untuk lokasi sistem.
sudo macguard quarantine ~/Library/LaunchAgents/com.evil.plist

# Kembalikan ke tempat semula. Default inert — TIDAK berjalan lagi.
macguard restore 20261002-101623-update_helper

# Lihat yang sedang ditahan.
macguard list

# Pastikan state MacGuard dan log-nya tidak dimanipulasi.
macguard selfcheck
```

## Perintah

| Perintah | Fungsi |
|---|---|
| `scan` | Pindai aplikasi, persistence, proses, jaringan, dan sistem |
| `inspect <path>` | Analisis mendalam satu file atau app bundle |
| `quarantine <path>` | Pindahkan item mencurigakan ke karantina dan hentikan jalannya |
| `restore <id>` | Kembalikan item dari karantina (inert kecuali `--reload`) |
| `list` | Daftar item karantina dan status verifikasinya |
| `purge <id>` | Hapus permanen item karantina — tidak bisa dibatalkan |
| `reseal` | Tandatangani ulang record yang dibuat sebelum digest integritas ada |
| `baseline` | Setujui, cabut, atau daftar item yang dipercaya |
| `sig` | Kelola database hash dan tanda tangan vendor lokal |
| `watch` | Scan berulang dengan interval dan laporkan temuan baru |
| `audit` | Tampilkan log aksi yang tahan manipulasi |
| `rules` | Daftar aturan deteksi yang aktif |
| `config` | Lihat atau ubah pengaturan scan persisten |
| `doctor` | Cetak diagnostik lingkungan |
| `selfcheck` | Verifikasi integritas state dan log MacGuard sendiri |

`macguard help` menampilkan daftar opsi lengkap.

## Scan

### Scope

`--scope <list>` menerima satu atau lebih dari:

- `apps` — app bundle, code signature, notarization
- `persistence` — LaunchAgents, LaunchDaemons, login item, cron, shell profile,
  `authorized_keys`, sudoers drop-in, configuration profile
- `processes` — proses yang berjalan dan listener
- `network` — kondisi jaringan
- `system` — pemeriksaan sistem menyeluruh
- `all` — semuanya (default)

```bash
macguard scan --scope persistence
macguard scan --scope apps,persistence
```

### Severity

`--min <severity>` menentukan ambang pelaporan:

`info` < `low` < `medium` < `high` < `critical`

Default `low`. Temuan pada ambang atau di atasnya dihitung sebagai ancaman dan
menghasilkan exit code `1`.

### Opsi yang berguna

```bash
macguard scan --dry-run                      # tidak mengubah apa pun
macguard scan --json ~/Desktop/scan.json     # laporan untuk mesin
macguard scan --html ~/Desktop/scan.html     # laporan untuk dibagikan
macguard scan --evidence                     # tampilkan semua bukti
macguard scan --progress                     # progres langsung
macguard scan --no-notarization              # lewati cek Gatekeeper (lebih cepat)
macguard scan --include-apple                # pindai juga aplikasi Apple
macguard scan --baseline                     # hormati ~/.macguard/baseline.json
```

`--no-notarization` perlu diketahui: cek notarization memanggil `spctl` dan
merupakan bagian terlambat dari scan aplikasi.

### Remediasi Otomatis

Ini bagian yang mengubah sistem Anda, jadi baca dulu sebelum memakai.

```bash
# Pratinjau dulu. Selalu lakukan ini.
sudo macguard scan --scope all --quarantine --quarantine-at critical --dry-run

# Baru yang sungguhan.
sudo macguard scan --scope all --quarantine --quarantine-at critical
```

- `--quarantine` mengaktifkan remediasi.
- `--quarantine-at <severity>` menentukan ambang auto-karantina. Default `high`.
- `--delete` menghapus permanen alih-alih mengkarantina. Tidak ada yang bisa
  membatalkan.
- `--dry-run` mengabaikan semua yang lain dan tidak menulis apa pun.
- `--allow-protected` mengizinkan menyentuh path yang dilindungi SIP.
  Berbahaya; biarkan mati kecuali Anda benar-benar tahu alasan Anda.

Remediasi mengelompokkan temuan berdasarkan bukti program, sehingga semua temuan
yang terlacak ke payload yang sama ditangani sebagai satu operasi, bukan satu
rule hit demi satu.

## Karantina

```bash
sudo macguard quarantine ~/Library/LaunchAgents/update_helper
```

Keluaran seperti ini:

```
✓ quarantined /Users/anda/Library/LaunchAgents/update_helper
  id       20261002-113538-update_helper
  payload  ~/Library/Application Support/MacGuard/Quarantine/20261002-113538-update_helper/update_helper
  restore  macguard restore 20261002-113538-update_helper
```

Yang terjadi:

1. Proses yang berjalan memakai file tersebut dibunuh.
2. Registrasi persistence yang menunjuk ke file itu di-unload.
3. File dipindahkan ke area karantina dan dikunci ke mode `000`.
4. Record bertanda tangan ditulis yang menjelaskan apa yang dipindahkan dan
   mengapa.

Opsi:

- `--dry-run` — tunjukkan apa yang akan terjadi, jangan ubah apa pun.
- `--delete` — hapus permanen.
- `--no-kill` — biarkan proses yang berjalan.

### Mengembalikan

```bash
macguard restore <id>
```

Restore **default inert**: file kembali ke lokasi aslinya tapi tidak
diregistrasikan ke `launchd`, jadi tidak mulai berjalan. Itu disengaja —
mengembalikan item persistence biasanya berarti mengembalikan persistence-nya
juga.

Agar item hidup kembali:

```bash
macguard restore <id> --reload
```

### Melihat Daftar

```bash
macguard list
```

Setiap entri menampilkan path asli, alasan, ukuran, SHA-256, dan status
verifikasi. Record yang tidak bisa diverifikasi ditampilkan sebagai `UNVERIFIED`
bukan disembunyikan, sehingga manipulasi atau record lama terlihat alih-alih
diabaikan diam-diam.

### Menghapus Permanen

```bash
sudo macguard purge <id>
```

Ini menghapus payload secara permanen. Tidak ada pemulihan. Lakukan purge hanya
setelah yakin Anda tidak ingin file itu kembali.

## Keputusan Kepercayaan

### Baseline

```bash
macguard baseline add /Applications/Firefox.app
macguard baseline list
macguard baseline remove /Applications/Firefox.app
macguard scan --baseline
```

Entri baseline disimpan di `~/.macguard/baseline.json` dan menahan temuan untuk
perangkat lunak yang sudah Anda putuskan untuk dipercaya.

### Aturan

```bash
macguard rules
```

19 aturan bawaan mencakup protokol cryptominer, download-lalu-jalankan, reverse
shell, akses kredensial, obfuscation, bypass Gatekeeper, injeksi dylib,
shell-sebagai-service, dan lainnya.

Tambahkan aturan Anda sendiri sebagai JSON array di `~/.macguard/rules.json`:

```json
[
  {
    "id": "MY-RULE-01",
    "severity": "HIGH",
    "title": "Kebijakan khusus",
    "detail": "Mengapa ini penting",
    "kind": "content",
    "patterns": ["pola-yang-mencurigakan"]
  }
]
```

`kind` adalah salah satu dari `content`, `path`, `process`, atau `bundleInfo`.

### Konfigurasi

```bash
macguard config
macguard config set --min high
macguard config set --no-notarization
```

Tersimpan di `~/.macguard/config.json`.

## Log Audit

Setiap karantina, restore, purge, dan perubahan baseline ditambahkan ke rantai
hash yang tahan manipulasi di direktori state.

```bash
macguard audit              # tampilkan entri terbaru
macguard audit --verify     # verifikasi seluruh rantai
```

Setiap entri memuat hash entri sebelumnya dan tanda tangan HMAC. Mengubah atau
menghapus entri merusak rantai dan `audit --verify` akan menyatakannya. Entri
yang tidak bisa diverifikasi diarsipkan ke file
`.unverifiable-<timestamp>.jsonl` terpisah, bukan diam-diam diterima.

Kunci mengikuti **pemilik direktori state**, bukan UID efektif. Record dan audit
selalu ditulis ke direktori state user, jadi kunci signing juga ada di sana —
termasuk ketika perintah dijalankan lewat `sudo`:

```
~/Library/Application Support/MacGuard/integrity.key
```

Hanya shell root sejati (tanpa `SUDO_USER`, tanpa state user) yang memakai kunci
root di `/var/db/macguard/integrity.key`. Konsekuensinya, `sudo macguard ...` menandatangani
dengan kunci yang bisa dibaca user, sehingga record tetap bisa diverifikasi dari
run biasa.

## Self-Check

```bash
macguard selfcheck
```

Memverifikasi:

- rantai audit
- kepemilikan dan izin direktori state serta karantina
- setiap record karantina
- bahwa alat sistem yang dipakai MacGuard (`spctl`, `codesign`, `launchctl`,
  `crontab`, `lsof`, `dscl`) belum diganti

Exit code `1` jika ada yang gagal. Berguna sebagai pemeriksaan integritas
berkala.

## Mode Watch

```bash
macguard watch --interval 300
```

Scan ulang setiap 5 menit dan laporkan temuan baru.

## Lokasi State

| Path | Isi |
|---|---|
| `~/Library/Application Support/MacGuard/` | Area karantina, record, log audit, kunci integritas user |
| `~/Library/Application Support/MacGuard/Quarantine/records/` | Satu record JSON bertanda tangan per item karantina |
| `/var/db/macguard/` | Kunci integritas milik root, saat dijalankan lewat `sudo` |
| `~/.macguard/` | Konfigurasi, baseline, aturan khusus |

## Exit Code

| Code | Arti |
|---|---|
| `0` | Bersih, atau perintah berhasil |
| `1` | Ada ancaman ditemukan, atau self-check gagal |
| `2` | Kesalahan penggunaan atau izin |

## Catatan Keamanan

- Mulai dengan `--dry-run`. Itu cara tercepat untuk membangun kepercayaan.
- Quarantine dan restore bisa dibalik. `purge` dan `--delete` tidak.
- Restore tidak mendaftarkan ulang persistence kecuali Anda memberi `--reload`.
- MacGuard menolak menyentuh path yang dilindungi SIP kecuali Anda memberi
  `--allow-protected`.
- Mengkarantina file di lokasi sistem butuh `sudo`.
- Payload yang dikarantina mode `000`, dan untuk item sistem, milik root.

## Pemisahan Hak Akses

Perilaku di bawah `sudo` punya beberapa nuansa yang perlu Anda tahu:

- State dan log audit tetap berada di direktori **user**, bukan `/var/root`,
  bahkan saat dijalankan dengan `sudo`.
- Penandatangan record memakai kunci yang **user bisa baca**, sehingga Anda
  bisa memverifikasi record karantina Anda sendiri tanpa `sudo`.
- Kepemilikan direktori dan file mengikuti akun pemilik state, bukan proses yang
  menjalankan. `sudo` tidak nimmt alih direktori Anda.

Kalau Anda melihat "signed with a key this machine no longer has", itu artinya
record ditandatangani dengan kunci yang sudah tidak terbaca. `sudo macguard reseal` akan menandatangani ulang, selama payload-nya
masih ada.

## Dokumentasi

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — cara komponen bekerja sama,
  modul per modul.
- [docs/FUNCTIONS.md](docs/FUNCTIONS.md) — apa yang dilakukan setiap file sumber
  dan setiap API publik.