# G - 8008 RP

Dashboard HR multi-kantor dan multi-group dengan:

- Masa aktif Paspor, Visa, Work Permit, dan Kontrak pada menu terpisah
- Peringatan Paspor 270 hari, Visa 60 hari, WP 60 hari
- Daftar staf per group
- Multi admin
- Google Authenticator 2FA berbeda untuk setiap admin
- Reset password dan reset 2FA admin oleh Super Admin
- Jadwal cuti mendatang yang sudah ACC
- Ex karyawan, blacklist, SP, notifikasi dashboard dan Telegram
- Logout otomatis setelah 60 menit tidak aktif

## Railway Variables

```env
NODE_ENV=production
APP_NAME=G - 8008 RP
DATA_DIR=/data
ADMIN_ID=ADM-0001
ADMIN_NAME=Super Admin
ADMIN_PASSWORD=GANTI_PASSWORD_KUAT
SYNC_ADMIN_ON_BOOT=true
SESSION_SECRET=GANTI_RANDOM_MINIMAL_32_KARAKTER
IDLE_TIMEOUT_MINUTES=60
ABSOLUTE_SESSION_HOURS=12
TIMEZONE=Asia/Jakarta
PASSPORT_ALERT_DAYS=270
VISA_ALERT_DAYS=60
WP_ALERT_DAYS=60
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

Pasang Railway Volume pada `/data`.

## Update Multi Fungsi
- Kantor dan group dapat diedit, dinonaktifkan, dan dihapus dengan validasi relasi data.
- Detail kantor menampilkan seluruh group/web dan staf di kantor tersebut.
- Data Visa, Paspor, WP, dan Kontrak dapat ditambah langsung dari menu masing-masing.
- Status proses dokumen: aktif, sedang diperpanjang oleh agent, menunggu approval, approved, atau ada kendala.
- Setelah approved, admin wajib memasukkan tanggal masa aktif terbaru dan dapat mengunggah file terbaru.
- Ex Karyawan dan Blacklist memiliki menu tersendiri dengan detail pop-up.
- Semua perubahan penting masuk audit log dan notifikasi dashboard/Telegram.

## Tambahan versi Cashbon & Sinkron Staf
- Hapus permanen staf hanya untuk Super Admin; seluruh data relasional ikut terhapus.
- Kontrak opsional: 1 tahun, 1,6 tahun, 2 tahun, 2,5 tahun, 3 tahun, atau tanggal bebas.
- Cashbon PT terhubung ke ID staf, lengkap dengan approval, konfirmasi lunas, dan history admin/agent.
- Saat memilih staf pada Cashbon atau Cuti, sistem menampilkan lama kerja, SP, cuti terakhir, dan cashbon aktif.
- Pencarian nama/ID staf tersedia di form Cashbon dan Cuti.
