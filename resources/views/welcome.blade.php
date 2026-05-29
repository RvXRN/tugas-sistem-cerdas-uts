<!DOCTYPE html>
<html lang="id" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSec | Advanced Threat Detection</title>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body class="bg-gray-950 text-gray-100 font-inter antialiased min-h-screen flex flex-col relative overflow-x-hidden">
    
    <!-- Background Effects -->
    <div class="fixed inset-0 pointer-events-none z-0">
        <div class="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-blue-600/10 blur-[120px]"></div>
        <div class="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-emerald-600/10 blur-[120px]"></div>
    </div>

    <!-- Navigation -->
    <nav class="relative z-50 border-b border-white/5 bg-gray-950/50 backdrop-blur-xl">
        <div class="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center text-white shadow-lg shadow-blue-500/20">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                </div>
                <span class="font-outfit font-bold text-2xl tracking-wide">Cyber<span class="text-blue-500">Sec</span></span>
            </div>
            <div class="hidden md:flex items-center gap-6">
                <a href="#features" class="text-sm font-medium text-gray-300 hover:text-white transition-colors">Fitur</a>
                <a href="https://api-cysec.bilikku.my.id/docs" target="_blank" class="text-sm font-medium text-gray-300 hover:text-white transition-colors flex items-center gap-1">
                    API Docs
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                </a>
                <div class="w-px h-6 bg-white/10 mx-2"></div>
                <a href="/login" class="text-sm font-bold text-white hover:text-blue-400 transition-colors">Masuk</a>
                <a href="/register" class="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-bold rounded-lg transition-all shadow-[0_0_15px_rgba(37,99,235,0.3)] hover:shadow-[0_0_25px_rgba(37,99,235,0.5)]">
                    Daftar Gratis
                </a>
            </div>
        </div>
    </nav>

    <!-- Hero Section -->
    <main class="flex-1 relative z-10 flex flex-col items-center justify-center pt-20 pb-32 px-6 text-center">
        <div class="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-bold uppercase tracking-wider mb-8">
            <span class="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
            Sistem Pakar & Machine Learning
        </div>
        
        <h1 class="text-5xl md:text-7xl font-outfit font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-white via-blue-100 to-gray-400 max-w-4xl leading-tight mb-8">
            Deteksi Cerdas,<br />Perlindungan Maksimal.
        </h1>
        
        <p class="text-lg md:text-xl text-gray-400 max-w-2xl mb-12 font-light leading-relaxed">
            Platform intelijen keamanan siber yang mengkombinasikan analisis pakar dan machine learning untuk memindai kerentanan web app secara otomatis dan akurat.
        </p>

        <div class="flex flex-col sm:flex-row items-center gap-4">
            <a href="/login" class="w-full sm:w-auto px-8 py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-bold text-lg transition-all shadow-[0_0_30px_rgba(37,99,235,0.4)] hover:shadow-[0_0_40px_rgba(37,99,235,0.6)] flex items-center justify-center gap-2">
                Mulai Deteksi Sekarang
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"></path></svg>
            </a>
            <a href="https://api-cysec.bilikku.my.id/docs" target="_blank" class="w-full sm:w-auto px-8 py-4 bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold text-lg transition-all border border-white/10 flex items-center justify-center gap-2">
                <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>
                Dokumentasi API
            </a>
        </div>
    </main>

    <!-- Features Section -->
    <section id="features" class="relative z-10 py-24 bg-gray-950/80 border-t border-white/5 backdrop-blur-lg">
        <div class="max-w-7xl mx-auto px-6">
            <div class="text-center mb-16">
                <h2 class="text-3xl md:text-4xl font-outfit font-bold text-white mb-4">Fitur Unggulan</h2>
                <p class="text-gray-400 max-w-2xl mx-auto">Kami menyediakan instrumen analisis keamanan tingkat lanjut untuk mengamankan aset digital Anda.</p>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                <!-- Feature 1 -->
                <div class="glass-panel p-8">
                    <div class="w-14 h-14 rounded-2xl bg-blue-500/10 text-blue-400 flex items-center justify-center mb-6">
                        <svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                    </div>
                    <h3 class="text-xl font-bold text-white mb-3">Active Scanner</h3>
                    <p class="text-gray-400 text-sm leading-relaxed">Pindai URL target secara otomatis untuk mendeteksi celah keamanan (seperti XSS, SQLi, CSRF) menggunakan payload dinamis.</p>
                </div>
                
                <!-- Feature 2 -->
                <div class="glass-panel p-8">
                    <div class="w-14 h-14 rounded-2xl bg-emerald-500/10 text-emerald-400 flex items-center justify-center mb-6">
                        <svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>
                    </div>
                    <h3 class="text-xl font-bold text-white mb-3">Manual Diagnostics</h3>
                    <p class="text-gray-400 text-sm leading-relaxed">Input gejala yang ditemukan pada log server Anda dan biarkan sistem pakar (Forward Chaining & Certainty Factor) menganalisis ancamannya.</p>
                </div>
                
                <!-- Feature 3 -->
                <div class="glass-panel p-8">
                    <div class="w-14 h-14 rounded-2xl bg-purple-500/10 text-purple-400 flex items-center justify-center mb-6">
                        <svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
                    </div>
                    <h3 class="text-xl font-bold text-white mb-3">API-First Architecture</h3>
                    <p class="text-gray-400 text-sm leading-relaxed">Akses secara langsung core engine kami melalui REST API berbasis FastAPI yang didokumentasikan sepenuhnya menggunakan OpenAPI.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="border-t border-white/5 py-8 mt-auto relative z-10">
        <div class="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4">
            <p class="text-sm text-gray-500">© 2026 CyberSec Intelligence. All rights reserved.</p>
            <div class="flex items-center gap-4">
                <a href="https://api-cysec.bilikku.my.id/docs" target="_blank" class="text-sm text-gray-500 hover:text-white transition-colors">API Reference</a>
                <a href="#" class="text-sm text-gray-500 hover:text-white transition-colors">Privacy</a>
                <a href="#" class="text-sm text-gray-500 hover:text-white transition-colors">Terms</a>
            </div>
        </div>
    </footer>
    
</body>
</html>
