# PuTTYgen untuk Mac

Aplikasi macOS dengan tampilan grafis untuk `puttygen` (PuTTY), dengan fitur yang mengikuti PuTTYgen di Windows. Tampilannya memakai Bootstrap 5 dan ikon Lucide di dalam WKWebView. Semua proses kunci dikerjakan oleh binary `puttygen` resmi.

## Fitur
- Membuat kunci RSA, DSA, ECDSA (nistp256/384/521), EdDSA (Ed25519/Ed448), dan SSH-1 RSA
- Memuat/import private key PuTTY (`.ppk`), OpenSSH, ssh.com, dan SSH-1
- Menyimpan public key (RFC 4716) dan private key `.ppk` versi 2 atau 3, dengan parameter Argon2 yang bisa diatur
- Export OpenSSH (format lama dan baru) serta ssh.com
- Komentar dan passphrase kunci, fingerprint SHA256/MD5
- Menambah, menghapus, dan melihat info sertifikat

## Build
Butuh Xcode Command Line Tools dan `puttygen` (`brew install putty`).

```bash
./build.sh
```

Hasilnya ada di `build/PuTTYgen.app`. Binary `puttygen` ikut dimasukkan ke dalam app.

## Catatan
- Opsi "proven primes" membuat `puttygen` 0.83 dari Homebrew crash. Pakai "probable primes" saja.
- Kunci yang sedang dibuka disimpan di folder sementara privat dan selalu terenkripsi dengan passphrase sesi acak.
