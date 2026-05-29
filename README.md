# CyberSec Web Application - Tugas Sistem Cerdas UTS

## Deskripsi
Aplikasi web berbasis Laravel yang berfungsi sebagai antarmuka (frontend) untuk sistem pakar dan machine learning deteksi serangan siber. Aplikasi ini terintegrasi dengan backend API FastAPI untuk melakukan analisis dan deteksi kerentanan/serangan cyber.

## Fitur Utama
- **Autentikasi:** Login dan Registrasi pengguna (JWT via Backend API)
- **Deteksi Manual:** Input gejala serangan manual untuk dianalisa sistem pakar (Certainty Factor & Forward Chaining)
- **Active Scanner:** Pemindaian URL otomatis untuk mendeteksi kerentanan dan payload (terintegrasi dengan ML Random Forest)
- **Riwayat Konsultasi:** Melihat riwayat deteksi yang pernah dilakukan
- **Referensi Serangan:** Knowledge base jenis-jenis serangan (SQL Injection, XSS, DDoS, dll)

## Persyaratan Sistem
- PHP 8.1 atau lebih baru
- Composer
- Node.js & NPM
- Backend API CyberSec berjalan di port `8081` (Local) atau URL Production

## Instalasi
1. Clone repositori
```bash
git clone https://github.com/RvXRN/tugas-sistem-cerdas-uts.git
cd tugas-sistem-cerdas-uts
```
2. Salin file environment
```bash
cp .env.example .env
```
3. Install dependensi PHP
```bash
composer install
```
4. Install dependensi Node.js
```bash
npm install && npm run build
```
5. Generate application key
```bash
php artisan key:generate
```
6. Jalankan server lokal
```bash
php artisan serve
```

Akses aplikasi di `http://localhost:8000`.

## Branching
- Pembangunan fitur utama dilakukan di branch `app`.
