# Referensi Fungsi MacGuard

Apa yang dilakukan setiap file sumber dan setiap API publik. Untuk hubungan antar
modul lihat [ARCHITECTURE.md](ARCHITECTURE.md); untuk penggunaan berbasis tugas
lihat [README](../README.md).

---

## Model.swift

Tipe nilai inti. Semua modul lain dibangun di atasnya.

### `Severity`

`info(0) < low(1) < medium(2) < high(3) < critical(4)`. `Codable`, `Comparable`,
`CaseIterable`. `label` mengembalikan nama tampilan huruf besar.

### `ThreatCategory`

Sepuluh kategori: `persistence`, `loginItem`, `signature`, `notarization`,
`process`, `network`, `heuristic`, `signatureDB`, `quarantine`, `system`.
`label` mengembalikan bentuk singkat huruf besar yang dipakai di laporan.

### `Evidence`

Satu observasi yang mendukung sebuah temuan: `kind`, `key`, `value`, `redacted`.
Redaksi penting karena nilai evidence bisa memuat rahasia — pola yang cocok bisa
memuat sebagian kredensial.

### `Finding`

Satu masalah yang terdeteksi.

- `id` — identifier stabil, lihat `makeID(subject:rule:)`
- `severity`, `category`, `title`, `detail`
- `subject` — path atau proses yang jadi bahan temuan
- `evidence` — nilai `Evidence` pendukung
- `remediation` — apa yang harus dilakukan

`makeID(subject:rule:)` menurunkan ID deterministik dari subject dan rule
sehingga scan berulang menghasilkan ID yang sama untuk temuan yang sama. Itulah
yang memungkinkan remediasi mengelompokkan temuan dan `watch` hanya melaporkan
yang baru.

### `ThreatReport`

Hasil scan: temuan, timestamp, metadata host, jumlah per severity.
`sortedFindings()` mengurutkan severity menurun, lalu subject.

### `QuarantineRecord`

Record bertanda tangan untuk satu item karantina.

Identitas: `id`, `originalPath`, `quarantinedAt`, `reason`, `findings`.

Apa yang ditangkap: `sha256`, `sizeBytes`, `isDirectory`, `backupManifest`
(mode dan kepemilikan yang tercatat).

Apa yang dilakukan: `killedPIDs`, `removedPersistencePaths`.

Integritas: `integrityDigest`, `integrityMAC`, `integrityKeyID`. Ketiganya opsional
supaya record yang dibuat sebelumnya masih bisa di-decode.

Siklus hidup: `payloadPath`, `restoredAt`, `deleted`.

Turunan: `isSigned`, `hasIntegrityDigest`.

### `BaselineEntry` / `Baseline`

Item yang disetujui dan tidak boleh dilaporkan temuannya. Tersimpan di
`~/.macguard/baseline.json`.

### `MacGuardVersion`

Konstanta versi, dilaporkan oleh `doctor`.

---

## Util.swift

### `Digesting`

- `sha256Hex(_ data: Data) -> String`
- `sha256Hex(ofFile path: String) -> String?` — streaming file; `nil` kalau tidak
  terbaca

### `CommandResult`

Hasil subprocess: `status`, `stdout`, `stderr`, `combined`, `succeeded`.

### `Shell`

Satu-satunya tempat perintah eksternal dijalankan.

- `sanitizedEnvironment() -> [String: String]` — membangun environment anak dari
  nol alih-alih mewarisi. Mempertahankan `PATH`, `HOME`, `USER`, locale;
  membuang sisanya sehingga variabel yang dikendalikan penyerang di environment
  induk tidak bisa memengaruhi subprocess.
- `run(_ launchPath:_ args:[String], timeout:) -> CommandResult` — mengeksekusi
  tanpa shell, jadi argumen tidak pernah di-parse ulang dan tidak bisa
  ditafsirkan sebagai sintaks shell. Saat euid 0 menolak menjalankan binary yang
  bukan milik root, sehingga alat yang bisa ditulis user tidak dijalankan sebagai
  root.
- `which(_ tool: String) -> String?`

### `PathUtil`

Query filesystem: `exists`, `isDirectory`, `size`, `mtime`,
`isWritableByCurrentUser`, `isWorldWritable`, `posixMode`, `owner`, `uid`, `gid`,
`isAppBundle`, `bundleExecutable`, `bundleIdentifier`, `bundleVersion`.

- `expand(_:)` — memperluas `~`
- `contractHome(_:)` — mengecilkan prefiks home kembali jadi `~` untuk tampilan

### `Home`

- `current` — home user. Di bawah `sudo`, mencari `SUDO_USER` lewat `dscl` supaya
  karantina mendarat di direktori user, bukan `/var/root`.
- `hasUserState -> Bool` — pertanyaan tunggal yang menentukan di mana state hidup
  dan key mana yang menandatangani. Benar di bawah `sudo` meski `geteuid()` 0.
- `homeDirectory(forUser:) -> String?` — membaca
  `NFSHomeDirectory: /Users/x` dari directory service dan mengambil nilai
  setelah titik dua. `nil` kecuali hasilnya path absolut yang menunjuk direktori
  yang ada. `internal`, sudah ada test-nya.
- `stateOwner -> (uid:gid:)?` — akun yang memiliki direktori state. Dasar dari
  pemilihan kepemilikan dan pemilihan kunci.
- `stateDir`, `configDir`, `quarantineDir` — masing-masing memanggil
  `ensureOwnedDir(_:)`, yang membuat direktori `0700` dan mengambil kepemilikan
  jika privilege lain yang membuatnya.

### `UserLookup`

`name(forUID:)` — lookup UID ke nama username dengan cache, supaya laporan
menampilkan `root` bukan `0`.

### `Xattr`

Bantuan extended attribute: `read`, `list`, `write`, `remove`. Dipakai untuk
penanda karantina.

---

## Security.swift

### `SecurityError`

`unsafeID`, `protectedPath`, `integrityMismatch`, `recordTampered`,
`untrustedBinary`, `notAbsolute`.

### `SecurePath`

- `isSIPProtected(_:) -> Bool` — cek runtime `SF_RESTRICTED` plus prefiks sistem
  hardcoded. Inilah yang membuat `quarantine /System/...` gagal kecuali
  `--allow-protected` diberikan.
- `normalize(_:)` — normalisasi leksikal, tanpa akses filesystem, berfungsi pada
  path yang belum ada
- `canonical(_:)` — path dengan symlink ter-resolve, `nil` kalau tidak bisa
- `isLexicallyContained(_:in:)` — cek keterania tekstual
- `isContained(_:in:)` — cek keterania kanonik
- `requireWritable(_:)` — memastikan setiap komponen path ada dan bisa ditulis
- `validateID(_:)` — menolak apa pun di luar `[A-Za-z0-9._-]` sebelum ID dipakai
  sebagai komponen filename
- `stripTrailingSlash(_:)`

### `IntegrityKey`

- `keyURL()` — path kunci root atau user. Mengikuti **pemilik direktori state**,
  bukan UID efektif: record ditulis ke home user bahkan di bawah `sudo`, jadi
  memilih berdasarkan `geteuid()` akan menandatanganinya dengan kunci root yang
  tidak bisa dibaca user.
- `isRootBacked() -> Bool`
- `load() throws -> SymmetricKey` — membaca, atau membuat kunci 32 byte baru mode
  `0600`. Kunci baru diserahkan ke pemilik state dir, bukan ke proses yang
  menjalankannya.
- `keyID(_:) -> String` — sidik jari pendek, dicatat di setiap tanda tangan
- `sign(_:with:) -> String` — HMAC-SHA256, hex
- `verify(_:message:with:) -> Bool` — perbandingan waktu konstan
- `trustedKeys() -> [(id: String, key: SymmetricKey)]` — kunci saat ini, root, dan
  user, sehingga record yang ditandatangani sebagai root bisa diverifikasi ketika
  dibaca sebagai user
- `key(forID:) -> SymmetricKey?`

### `HashChain`

Log audit append-only dengan hash chaining dan HMAC per entri.

Field `Entry`: `at`, `actor`, `euid`, `action`, `target`, `detail`, `prev`,
`hash`, `mac`, `keyID`.

- `append(action:target:detail:)` — menautkan ke entri sebelumnya, hash, tanda
  tangan. Kalau kunci tidak tersedia entri ditulis tanpa tanda tangan, dan
  verifikasi lalu menolak rantai itu.
- `verify() -> (ok: Bool, checked: Int, brokenAt: Int?)` — menelusuri rantai.
  Gagal pada ketidakcocokan hash, tautan `prev` rusak, baris tidak bisa
  di-decode, MAC hilang, atau penandatangan yang tidak dipercaya. Mengarsipkan
  rantai yang tidak bisa dibuktikan sebelum mengembalikan failure.
- `rotateIfUndecodable() -> String?` — mengarsipkan log yang berisi baris tidak
  terbaca, mengembalikan path arsip
- `rotateIfUnattestable() -> String?` — mengarsipkan rantai yang tandatangannya
  buruk atau hilang
- `readAll() -> [Entry]`, `lineCount() -> Int`, `tail(_:) -> [String]`
- `lastVerificationFailure() -> String?` — kenapa verifikasi terakhir gagal
- `isFullySigned() -> Bool`

Kedua metode rotasi menulis ke `audit.unverifiable-<timestamp>.jsonl` dan
meninggalkan file asli. Bukti yang rusak diarsipkan, tidak pernah dihapus.

### `SecureFile`

- `writeAtomic(_:to:mode:) -> Bool` — file temp di direktori yang sama, `fsync`,
  rename atomik. Membuka dengan `O_NOFOLLOW` sehingga tidak menulis lewat
  symlink.
- `append(_:to:)` — menambahkan satu baris, juga `O_NOFOLLOW`
- `lockDown(_:mode:uid:gid:)` — menetapkan mode dan kepemilikan secara eksplisit

---

## Rules.swift

### `RuleScope`

Scanner mana yang berlaku untuk sebuah aturan: `content`, `path`, `process`,
`bundleInfo`.

### `ScanRule`

Definisi aturan yang bisa di-`Codable`: `id`, `title`, `severity`, `category`,
`scope`, `regex`, `literals`, `remediation`, `pathPrefixes`, `ignoreApplePaths`.

### `RuleEngine`

- `loadDefault(extraRulesFrom:) -> RuleEngine` — aturan bawaan plus
  `~/.macguard/rules.json`
- `scanPath(_:) -> [RuleMatch]` — aturan scope path
- `scanStrings(_:path:) -> [RuleMatch]` — aturan scope content terhadap string
  yang diekstrak
- `scanProcess(name:path:args:) -> [RuleMatch]` — aturan scope process
- `scanBundleInfo(_:path:) -> [RuleMatch]` — aturan metadata bundle

### `ApplePaths`

`isApplePath(_:)`, `isWritableByUser(_:)`, `isDevelopmentPath(_:)`. Dipakai agar
tidak menandai tooling Apple sendiri, dan mengenali direktori pengembang yang
wajar menyimpan executable.

### `DefaultRules`

19 aturan bawaan, mencakup: protokol pool cryptominer, download-lalu-jalankan,
reverse shell, akses kredensial dan keychain, obfuscation decode-lalu-jalankan,
penonaktifan Gatekeeper dan SIP, injeksi dylib, pemasangan persistence
LaunchAgent, akses database kredensial browser, escalate privilege dan
permanenan sudoers, manipulasi history, penyamaran hash, pemaketan UPX,
executable di direktori sementara, executable tersembunyi di dot-directory,
listener netcat/socat, binary shell berjalan sebagai service, dan bundle yang
memasang helper tanpa bundle identifier.

### `SignatureDatabase`

Database hash dan vendor lokal.

- `load() -> SignatureDatabase`
- `save() throws`
- `lookup(sha256:) -> HashSignature?`
- `isTrusted(teamID:bundleID:) -> Bool`
- `importSignatures(from:) throws`
- `add(_:)`, `addTrustedVendor(teamID:bundlePrefixes:)`

### `StringExtractor`

- `asciiStrings(from:minLength:limit:) -> [String]` — rentetan ASCII printable
  dari data binary, untuk aturan content
- `head(ofFile:maxBytes:) -> Data?` — baca terbatas, supaya memindai binary besar
  tidak menghabiskan memori

---

## Heuristics.swift

### `AnalyzedItem`

Properti yang dikumpulkan tentang satu file: path, ukuran, mode, pemilik, apakah
executable, SHA-256, entropy, extended attribute, info signature.

### `Heuristics`

- `analyze(path:) -> AnalyzedItem`
- `findings(for:) -> [Finding]` — penilaian berbasis properti: entropy tinggi
  yang mengindikasikan packing, bit executable pada tipe file yang tidak
  semestinya executable, lokasi tersembunyi, penanda karantina dari tool lain
- `isBaselineApproved(_:) -> Bool`

### `Shannon`

`entropy(_:) -> Double` — entropy Shannon dalam bit per byte. Nilai tinggi
mengindikasikan kompresi atau enkripsi.

---

## Detector.swift

### `ScanScope`

`all`, `apps`, `persistence`, `processes`, `network`, `system`.

### `Detector`

- `scan(scopes:progress:) -> ThreatReport` — menjalankan scope yang diminta dan
  menggabungkan temuan
- `persistenceFindings() -> [Finding]`
- `processFindings() -> [Finding]`
- `networkFindings() -> [Finding]`
- `systemFindings() -> [Finding]`

### `HostInfo`

Metadata host yang disertakan ke laporan: versi OS, model, uptime, user efektif.

---

## PersistenceScanner.swift

MEnumerasi semua yang bisa bertahan melewati reboot.

### `PersistenceItem`

`kind` (`launchAgent`, `launchDaemon`, `startupItem`, `loginItem`, `cron`,
`sshKeys`, `shellProfile`, `sudoers`, `kernelExtension`, `configurationProfile`),
`label`, `plistPath`, `executables`, `runAtLoad`, `keepAlive`, `environment`,
`rawDict`.

Lokasi yang dipindai:

- `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`,
  `/Users/Shared/LaunchAgents`, dan padanannya di `/System/Library`
- login item dari database Background Task Management di Ventura+
- crontab user saat ini, ditambah `/etc/cron.d` dan `/usr/lib/cron/tabs`
- shell profile, `authorized_keys`, sudoers drop-in, configuration profile,
  kernel extension

---

## ProcessScanner.swift

### `ProcInfo`

PID, parent PID, user, nama, path, argumen, CPU, memori.

### `ListeningSocket`

Alamat lokal dan remote, port, state, PID pemilik.

### `ProcessScanner`

- `allProcesses() -> [ProcInfo]`
- `buildTree(_:) -> [Int32: [ProcInfo]]` — parent ke anak
- `listeningSockets() -> [ListeningSocket]`
- `killTree(pid:timeout:) -> Bool` — membunuh proses beserta keturunannya.
  Keturunan lebih dulu, supaya parent tidak sempat membuat ulang
  anak-anaknya saat mereka sedang dihentikan.

---

## AppScanner.swift

### `Candidate`

App bundle yang akan diperiksa: path dan apakah itu aplikasi sistem Apple.

### `AppScanner`

- `appDirectories() -> [String]` — `/Applications`, `/Applications/Utilities`,
  `~/Applications`
- `hotDirectories() -> [String]` — lokasi yang bisa ditulis user di mana bundle
  tak terduga sering muncul
- `candidates(includeAppleApps:followPersistence:) -> [Candidate]`
- `appleToolNames() -> Set<String>` — nama yang tidak boleh ditandai mencurigakan

---

## CodeSignature.swift

### `SignatureInfo`

`verdict` (`.valid`, `.invalid`, `.unsigned`, `.adHoc`, `.notCode`, `.unchecked`),
`teamID`, `signingIdentifier`, `authority`, `isPlatformBinary`,
`hasHardenedRuntime`, `notarized`, `gatekeeperDetail`, `errors`.

`isThirdPartySigned` adalah pengecekan praktis untuk "ditandatangani seseorang
yang bukan Apple".

### `CodeSignatureVerifier`

- `verify(path:checkNotarization:) -> SignatureInfo` — menjalankan `codesign`
  dan, kalau `checkNotarization` diaktifkan, `spctl`. Cek notarization adalah
  bagian terlambat dari scan, itulah sebabnya `--no-notarization` ada.
- `hasSignature(path:) -> Bool`
- `entitlements(path:) -> [String: Any]`

---

## Quarantine.swift

### `QuarantineOptions`

`dryRun`, `deleteInsteadOfQuarantine`, `killProcesses` (default `true`),
`reloadAfterRestore` (default `false`), `allowProtectedPath`.

### `QuarantineError`

`notFound`, `alreadyRestored`, `notQuarantined`, `moveFailed`,
`integrityFailed`.

### `QuarantineEngine`

- `quarantine(path:reason:options:) throws -> QuarantineRecord` — validasi, bunuh
  proses, unload persistence, pindahkan, kunci ke mode `000`, seal, tulis record
- `restore(id:options:) throws -> QuarantineRecord` — kembalikan dan pulihkan mode
  yang tercatat. Tidak mendaftarkan ulang persistence kecuali `reloadAfterRestore`.
- `list() -> [QuarantineRecord]` — menyertakan record yang tidak bisa
  diverifikasi, ditandai, bukan difilter keluar
- `load(id:) throws -> QuarantineRecord`
- `save(_:) throws`
- `runningProcesses(usingBinaryAt:) -> [ProcInfo]`
- `seal(_:) static throws` — hitung digest, tandatangan
- `validate(_:) static throws` — hitung ulang digest, verifikasi HMAC terhadap
  kunci yang dipercaya, pastikan payloadPath berada di area karantina
- `saveRecord(_:) static throws` — menulis record lalu menyerahkannya ke pemilik
  state dir, supaya record yang ditulis di bawah `sudo` tidak tertinggal root-owned
- `isLaunchItem(_:) static -> Bool`
- `launchLabel(plist:) static -> String` — dibersihkan sebelum dipakai sebagai
  target `domain/label`
- `unloadLaunchItem(plist:) static -> Bool` — `bootout` dengan domain dan label
  eksplisit. Tanpa fallback ke `unload` biasa yang berlaku ke seluruh domain dan
  bisa mengeluarkan sesi GUI.
- `loadLaunchItem(plist:) static -> Bool`

### `purge(id:) throws`

Penghapusan permanen. Area karantina diverifikasi milik user saat ini terlebih
dahulu, karena payload mode `000` milik root tidak bisa dihapus user biasa dan
kegagalan senyap akan menyesatkan.

---

## Config.swift

### `ScanConfig`

`minSeverity`, `includeAppleBinaries`, `checkNotarization`,
`maxBytesPerBinary`, `followLaunchAgentTargets`, `maxProcessesDeepScan`.

`load()` dan `save(_:)` membaca dan menulis `~/.macguard/config.json`.

### `AuditLog`

Fasad tipis di atas `HashChain` supaya pemanggil tidak perlu menyusun rantainya
sendiri.

`record(action:target:detail:)`, `tail(_:)`, `verify()`,
`lineCount()`, `lastVerificationFailure()`, `isFullySigned()`.

---

## Reporter.swift

### `Theme`

Bantuan warna ANSI: `red`, `orange`, `yellow`, `blue`, `green`, `bold`, `dim`,
`severity(_:_:)`, `severityBadge(_:)`.

### `Reporter`

- `render(_:showEvidence:) -> String` — laporan terminal
- `summary(_:) -> String` — jumlah dalam satu baris
- `json(_:) -> String`
- `html(_:) -> String` — laporan HTML mandiri

### `BaselineStore`

`load() -> Baseline`, `save(_:) throws` — `~/.macguard/baseline.json`.

---

## main.swift

Entry point CLI. Parsing argumen, cek privilege, dan satu fungsi per perintah.

- `commandScan`, `commandInspect`, `commandQuarantine`, `commandRestore`,
  `commandList`, `commandPurge`, `commandReseal`, `commandBaseline`,
  `commandSig`, `commandWatch`, `commandAudit`, `commandRules`, `commandConfig`,
  `commandDoctor`, `commandSelfCheck`
- `requireRootIfNeeded(_:)` — menolak operasi sistem tanpa root dan mencetak
  perintah persis untuk dijalankan ulang
- Perencana remediasi — mengelompokkan temuan berdasarkan bukti program sehingga
  semua temuan yang terlacak ke payload yang sama ditangani sebagai satu operasi

Exit code: `0` bersih, `1` temuan ancaman atau self-check gagal, `2` kesalahan
penggunaan atau izin.

---

## Tests

`SecurityTests.swift`:

| Suite | Cakupan |
|---|---|
| Path validation | Traversal, escape absolut dan relatif, kebijakan SIP |
| Environment sanitisation | Pembuangan environment subprocess |
| Integrity signing | HMAC sign/verify, key ID, kunci tak dipercaya |
| Signed quarantine records | Penyatupan, deteksi manipulasi, keterania |
| Audit hash chain | Append, verify, deteksi edit, rotasi |
| Quarantine record integrity | Decode dan validasi record lama |
| Re-sealing legacy records | Payload cocok diterima; hilang atau berubah ditolak |
| Secure file IO | Tulis atomik, append, penolakan symlink, pembersihan temp |
| Home directory resolution | Parsing `dscl`; state dir tidak pernah ke `/var/root` |

`PrivilegeSeparationTests` — 4 test: kepemilikan state mengikuti user, kunci
penandatangan bisa dibaca user, kunci baru tidak milik root, dan
`hasUserState` terdeteksi pada sesi user.

`SmokeTests.swift` — 5 test: batas entropy, pelaporan ukuran file tunggal, dan
stabilitas digest.

Total 69 test di 11 suite (termasuk 5 smoke test).

## Batas yang diketahui

Semua test berjalan tanpa `SUDO_USER`. Perilaku `sudo` sungguhan — yang menjadi
sumber lima bug selama pengerjaan ini — belum punya test integrasi. Unit test
mengunci logikanya, tetapi tidak ada test yang menjalankan binary di bawah `sudo`
sungguhan dan memeriksa kepemilikan serta kunci yang dihasilkan.