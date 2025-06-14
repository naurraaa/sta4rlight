# Sistem Pemesanan Tiket Konser

#### buat project baru

1. pastikan sudah install nodejs dan github desktop.
2. buka terminal dan pilih folder tempat project.
3. jalankan `npm create vue@latest`.
4. Project name isi dengan `Sistem Pemesanan Tiket Konser`.
5. untuk feature pilih `Router` saja.

##### menjalankan project

1. buka folder `Sistem Pemesanan Tiket Konser` di vscode.
2. buka terminal yang ada di vscode dengan ctrl + `.
3. install dependency project dengan menjalankan `npm install` di terminal.
4. jalankan project dengan menjalankan `npm run dev` di terminal.

#### setting github di vscode

1. buat repository di github dengan nama repo `Sistem Pemesanan Tiket Konser`.
2. masuk ke menu source controle di github dan pilih `initialize repository`.
3. masukkan `README.md` ke stage dan commit.
4. tambahkan remote github.
5. publish/push/sync ke github.

#### setting cloudflare

1. install wrangler dan cloudflare/vite-plugin degan menjalankan `npm install -D @cloudflare/vite-plugin wrangler` di terminal.
2. setting cloudflare di `vite.config.js`.
3. buat dan setting `wrangler.jsonc`
4. buat file `index.js` di folder api untuk backend.
5. create worker di cloudflare dengan memilih `Import a repository` dan pilih `Sistem Pemesanan Tiket Konser`.
6. biarkan setting standart pilih build.

#### setting backend

1. install hono dengan menjalankan `npm install hono` di terminal.
2. setting file `api/index.js` menggunakan hono.
3. buat database di cloudflare kemudian ambil id nya.
4. pada `wrangler.json` setting `d1_databases`.
5. buat migrasi dengan menjalankan `wrangler d1 migrations create Sistem Pemesanan Tiket Konser create_products`.
6. setting file `0001_create_products.sql`.
7. jalankan migrasi dengan `wrangler d1 migrations apply Sistem Pemesanan Tiket Konser`.
8. setting api pada route `/api/products`.
