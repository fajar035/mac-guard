# Arsitektur MacGuard

Sekitar 4.700 baris kode library plus CLI 815 baris. Tanpa dependensi pihak
ketiga — hanya Foundation dan CryptoKit.

## Bentuk

```
Sources/macguard/main.swift        CLI: parsing argumen, dispatch, output
Sources/MacGuardKit/
  Model.swift                     Tipe data: Severity, Finding, ThreatReport,
                                  QuarantineRecord, Baseline
  Config.swift                    Persistensi ScanConfig + fasad AuditLog
  Util.swift                      Digesting, Shell, PathUtil, Home, Xattr
  Security.swift                  SecurePath, IntegrityKey, HashChain, SecureFile
  Rules.swift                     RuleEngine, 19 aturan bawaan, database signature
  Heuristics.swift                Analisis per-file, entropy, cek baseline
  Detector.swift                  Orkestrasi scan lintas scope
  PersistenceScanner.swift        LaunchAgents, cron, login item, sudoers...
  ProcessScanner.swift            Tabel proses, socket, kill tree
  AppScanner.swift                Enumerasi kandidat aplikasi
  CodeSignature.swift             Verifikasi codesign / spctl
  Quarantine.swift                Quarantine, restore, purge, kontrol launchctl
  Reporter.swift                  Output terminal, JSON, HTML; penyimpanan Baseline
```

## Alur sebuah scan

```
main.swift commandScan
  │
  ├─ ScanConfig.load()                    ~/.macguard/config.json
  ├─ RuleEngine.loadDefault()             aturan bawaan + ~/.macguard/rules.json
  │
  └─ Detector.scan(scopes:)
       ├─ persistenceFindings()   PersistenceScanner → rule scan → Finding[]
       ├─ appFindings()           AppScanner → CodeSignatureVerifier → Finding[]
       ├─ processFindings()       ProcessScanner.allProcesses() → Finding[]
       ├─ networkFindings()       socket → Finding[]
       └─ systemFindings()        HostInfo checks → Finding[]
              │
              └─ Heuristics.analyze + findings()   properti per-file
                    │
                    └─ ThreatReport  ──►  Reporter.render / .json / .html
```

Kalau `--quarantine` aktif, temuan dikelompokkan berdasarkan bukti `program` dan
tiap kelompok di atas ambang menjadi satu operasi karantina.

## Aturan lapisan

Desain memisahkan tiga hal, dan arah dependensinya penting:

1. **Observasi** — `PersistenceScanner`, `ProcessScanner`, `AppScanner`,
   `CodeSignatureVerifier`. Read-only. Tidak tahu apa itu karantina atau
   penandatanganan.
2. **Penilaian** — `RuleEngine`, `Heuristics`, `Detector`. Mengubah observasi
   menjadi nilai `Finding`. Tetap tidak menulis.
3. **Tindakan** — `QuarantineEngine`, `HashChain`, `SecureFile`. Satu-satunya
   kode yang mengubah sistem, dan satu-satunya yang menandatangani.

`Security.swift` ada di bawah ketiganya. Tidak ada lapisan observasi atau
penilaian yang bergantung padanya.

## Primitif keamanan

### SecurePath

Penanganan path adalah permukaan serangan utama untuk alat yang menerima path dari
user lalu memindahkan file. `SecurePath` menangani:

- `normalize(_:)` — normalisasi leksikal. Menyelesaikan `..` secara tekstual tanpa
  menyentuh filesystem, jadi berfungsi pada path yang belum ada.
- `isLexicallyContained(_:in:)` — cek keteranía tekstual. Alasan yang sama.
- `canonical(_:)` — menyelesaikan symlink untuk path yang ada.
- `isContained(_:in:)` — keteranía kanonik, untuk path yang ada.
- `isSIPProtected(_:)` — menggabungkan flag runtime `SF_RESTRICTED` dengan daftar
  prefiks sistem hardcoded.
- `validateID(_:)` — ID karantina jadi komponen path, jadi dibatasi ke karakter
  aman sebelum digabungkan ke apa pun.

Dua fungsi keteranía itu sengaja terpisah. Cek path traversal yang berjalan
sebelum pemindahan harus bekerja pada path sebagaimana diberikan; yang berjalan
sesudah pemindahan harus bekerja pada apa yang benar-benar ada di disk.

### IntegrityKey

Kunci penandatanganan HMAC-SHA256. Lokasi mengikuti **pemilik state**, bukan
`geteuid()`:

- state user ada → `~/Library/Application Support/MacGuard/integrity.key`
- shell root sejati (tanpa state user) → `/var/db/macguard/integrity.key`

Keduanya mode `0600`. Ini penting: record dan audit ditulis ke direktori state
user bahkan ketika berjalan di bawah `sudo`. Kalau kunci ikut `geteuid()`, record
ditandatangani dengan kunci root yang tidak bisa dibaca user, dan setiap record
milik user menjadi tidak bisa diverifikasi dari run biasa selamanya. Prinsipnya:
tandatangani dengan kunci yang sama dengan lokasi data yang sedang ditandatangani.

`trustedKeys()` mengembalikan kunci saat ini plus kunci root dan user, sehingga
record yang ditandatangani sebagai root tetap bisa diverifikasi ketika dibaca
kembali sebagai user.

`verify(_:message:with:)` membandingkan dalam waktu konstan.

### HashChain

Log audit JSONL append-only. Setiap entri menyimpan:

- `prev` — hash entri sebelumnya
- `hash` — SHA-256 dari isi entri termasuk `prev`
- `mac` — HMAC entri memakai `IntegrityKey`
- `keyID` — kunci mana yang menghasilkan MAC

`verify()` menelusuri rantai dan gagal pada: ketidakcocokan `prev`, `hash` buruk,
baris yang tidak bisa di-decode, MAC yang hilang, atau tanda tangan dari kunci
yang tidak dipercaya.

`rotateIfUndecodable()` dan `rotateIfUnattestable()` memindahkan log yang tidak
bisa diverifikasi ke `audit.unverifiable-<timestamp>.jsonl` dan memulai rantai
baru. Bukti yang rusak diarsipkan, tidak dihapus — manipulasinya tetap terlihat.

### SecureFile

`writeAtomic(_:to:mode:)` — tulis ke file temp di direktori yang sama, `fsync`,
lalu rename atomik. Membuka dengan `O_NOFOLLOW` sehingga tidak menulis melalui
symlink. Membersihkan file temp di setiap jalur gagal.

`append(_:to:)` — perlakuan `O_NOFOLLOW` yang sama, menambahkan satu baris.

## Karantina

`QuarantineEngine.quarantine(path:reason:options:)`:

1. Validasi path terhadap kebijakan SIP dan keterania.
2. Bunuh proses yang memakai file tersebut (`killProcesses`, default aktif).
3. Unload persistence yang menunjuk ke sana.
4. Catat mode dan kepemilikan file di `backupManifest`.
5. Pindahkan ke area karantina, kunci ke mode `000`.
6. Susun record, `seal()` (digest + HMAC), tulis.

Urutannya penting. Payload dipindahkan sebelum record ditulis, jadi kalau
penulisan record gagal, kode memeriksa payload setidaknya masih ada dan melempar
error, bukan mengembalikan sukses untuk item tanpa jejak bertanda tangan.

`restore(id:options:)` mengembalikan file ke lokasi semula dan memulihkan mode
yang tercatat. Restore **tidak** mendaftarkan ulang persistence kecuali
`reloadAfterRestore` diaktifkan — mengembalikan LaunchAgent biasanya berarti
mengembalikan LaunchAgent-nya, jadi itu opsi eksplisit lewat `--reload`.

`purge(id:)` menghapus permanen. Area karantina diverifikasi milik user saat ini
terlebih dahulu, karena payload mode `000` milik root memang tidak bisa dihapus
user biasa, dan kegagalan senyap di sana akan menyesatkan.

### Penandatanganan record

`seal(_:)` menghitung digest dari field yang menggambarkan *apa yang diambil*:
`backupManifest`, `killedPIDs`, `removedPersistencePaths`, plus field identitas.
Lalu menandatangani digest itu.

`validate(_:)` menghitung ulang digest, mengecek HMAC terhadap kunci yang
dipercaya, dan memastikan `payloadPath` secara leksikal berada di dalam area
karantina.

Digest saja tidak cukup. Record adalah file JSON biasa di direktori milik user,
jadi penyerang bisa mengubah field dan menghitung ulang digest. HMAC yang
membuatnya tidak bisa dipalsukan tanpa kunci.

Record yang ditulis sebelum field integritas ada tetap bisa di-decode — `digest`,
`mac`, dan `keyID` semuanya opsional — tapi gagal validasi dan muncul sebagai
`UNVERIFIED` sampai `reseal` menandatanganinya. `reseal` menolak record yang
payload-nya hilang atau whose byte-nya sudah tidak cocok dengan hash yang
dicatat.

### Pemilihan kunci dan kepemilikan

Kunci penandatangan dan kepemilikan direktori mengikuti **akun pemilik state**,
bukan UID efektif proses. Ini satu keputusan untuk dua hal yang sebelumnya
terpisah dan saling bertentangan.

Di bawah `sudo`, `geteuid()` adalah `0` sementara record tetap ditulis ke
direktori user. Kalau kunci dan kepemilikan mengikuti `geteuid()`, hasilnya
record ditandatangani dengan kunci root yang tidak bisa dibaca user, dan
direktori state diambil alih root sehingga user terkunci dari karantinanya
sendiri.

Kebutuhannya bisa diringkas jadi satu pertanyaan: `Home.hasUserState` — apakah
MacGuard bertindak atas nama akun user nyata. Kalau ya, state dan kunci milik user
tersebut. Root shell asli tidak punya direktori user untuk bertindak atas namanya,
jadi memakai kunci root.

## Penanganan launchctl

`launchDomain()` menentukan domain target dari `SUDO_UID`, sehingga MacGuard
yang dijalankan sebagai root bertindak pada sesi GUI manusia, bukan sesi root.

Label dibersihkan sebelum dipakai sebagai target `domain/label`.

Tidak ada fallback ke `launchctl unload` biasa. `unload` berlaku untuk seluruh
domain, jadi salah target akan mengeluarkan sesi GUI. `bootout` dengan domain dan
label eksplisit adalah operasi yang bedanya.

## Pemisahan root dan user

Tiga tempat:

- `Home.current` — di bawah `sudo`, mencari home user dari `SUDO_USER` via
  `dscl`, sehingga karantina mendarat di direktori state user, bukan
  `/var/root`. Nilainya divalidasi sebagai direktori yang ada sebelum dipakai.
- `ensureOwnedDir(_:)` — membuat direktori state mode `0700` dan mengambil
  kepemilikan jika pihak lain yang membuatnya. Inilah yang mencegah file milik
  root menghalangi jalannya user non-privilege, dan sebaliknya.
- `IntegrityKey` — kunci root dan user terpisah, dengan `trustedKeys()` yang
  menjembatani verifikasi di keduanya.

Kode parsing `dscl` perlu diperhatikan: `dscl . -read /Users/x
NFSHomeDirectory` mencetak `NFSHomeDirectory: /Users/x`, jadi nilai diambil dari
sesudah titik dua. Memecah per baris menghasilkan seluruh garis berlabel, yang
tidak terlihat seperti path, lalu diam-diam jatuh ke `NSHomeDirectory()` — yaitu
`/var/root` di bawah sudo.

## Pengujian

`Tests/MacGuardKitTests/SecurityTests.swift` — traversal dan
kebijakan SIP `SecurePath`, sanitasi environment subprocess, penandatangan HMAC,
penyatukan dan deteksi manipulasi record, verifikasi dan rotasi rantai audit,
perilaku reseal, dan penolakan symlink di `SecureFile`.

`SmokeTests.swift` — 5 test: batas entropy, pelaporan ukuran file tunggal, dan
stabilitas digest.

`PrivilegeSeparationTests` — mengunci bahwa kepemilikan state dan pemilihan kunci
mengikuti akun pemilik state.

Fixture test yang butuh path di dalam area karantina memakai helper
`scratchInQuarantine` yang membuat direktori `.test-*` dan menghapusnya di
`defer` milik pemanggil. Helper mengembalikan path, bukan membersihkan sendiri,
karena `defer` di dalam helper akan menghapus fixture sebelum test bisa
memeriksa.

## Batas pengujian saat ini

Semua test berjalan sebagai user biasa tanpa `SUDO_USER` terisi. Perilaku di bawah
`sudo` yang sebenarnya belum diuji otomatis — logika pemilihan kunci dan
kepemilikan terkunci oleh unit test, tetapi tidak ada test yang menjalankan
binary di bawah `sudo` sungguhan dan memeriksa kepemilikan hasilnya. Itu celah
yang diketahui, bukan hal yang sudah tertutup.