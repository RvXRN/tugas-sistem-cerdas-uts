<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSec | Dashboard</title>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body class="bg-gray-950 text-gray-100 font-inter antialiased" x-data="appLayout()">
    
    <div class="flex min-h-screen">
        <!-- Sidebar -->
        <aside class="w-64 fixed inset-y-0 left-0 bg-slate-900/80 backdrop-blur-xl border-r border-white/5 z-50 flex flex-col transition-transform duration-300" 
               :class="{'translate-x-0': sidebarOpen, '-translate-x-full': !sidebarOpen, 'md:translate-x-0': true}">
            <div class="p-6 border-b border-white/5 flex items-center gap-3">
                <div class="w-8 h-8 rounded bg-blue-500/20 text-blue-500 flex items-center justify-center">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                </div>
                <span class="font-outfit font-bold text-xl tracking-wide">Cyber<span class="text-blue-500">Sec</span></span>
            </div>
            
            <nav class="flex-1 p-4 space-y-2 overflow-y-auto">
                <a href="/" class="flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300"
                   :class="isRoute('/') ? 'bg-blue-500/10 text-blue-500 border-l-2 border-blue-500' : 'text-gray-400 hover:bg-white/5 hover:text-gray-200'">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path></svg>
                    <span class="font-medium">Dashboard</span>
                </a>
                <a href="/history" class="flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300"
                   :class="isRoute('/history') ? 'bg-blue-500/10 text-blue-500 border-l-2 border-blue-500' : 'text-gray-400 hover:bg-white/5 hover:text-gray-200'">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <span class="font-medium">History</span>
                </a>
                <a href="/attacks" class="flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300"
                   :class="isRoute('/attacks') ? 'bg-blue-500/10 text-blue-500 border-l-2 border-blue-500' : 'text-gray-400 hover:bg-white/5 hover:text-gray-200'">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                    <span class="font-medium">Attacks Ref</span>
                </a>
                <a href="/datasets" class="flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300"
                   :class="isRoute('/datasets') ? 'bg-blue-500/10 text-blue-500 border-l-2 border-blue-500' : 'text-gray-400 hover:bg-white/5 hover:text-gray-200'">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"></path></svg>
                    <span class="font-medium">Datasets</span>
                </a>
            </nav>
            
            <div class="p-4 border-t border-white/5">
                <!-- User Profile Card -->
                <div class="flex items-center gap-3 px-3 py-3 mb-2 bg-white/5 rounded-xl border border-white/10">
                    <div class="w-10 h-10 rounded-full bg-blue-600 flex items-center justify-center font-outfit font-bold text-white uppercase text-lg" x-text="username ? username.charAt(0) : 'U'"></div>
                    <div class="flex-1 overflow-hidden">
                        <p class="text-sm font-bold text-gray-200 truncate" x-text="username || 'Administrator'"></p>
                        <p class="text-xs text-emerald-400 flex items-center gap-1">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span> Online
                        </p>
                    </div>
                </div>

                <button @click="logout" class="w-full flex items-center gap-3 px-4 py-3 text-red-400 hover:bg-red-500/10 hover:text-red-300 rounded-xl transition-all duration-300">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
                    <span class="font-medium">Logout</span>
                </button>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="flex-1 md:ml-64 transition-all duration-300">
            <!-- Mobile Header -->
            <header class="md:hidden flex items-center justify-between p-4 bg-slate-900/80 backdrop-blur-md border-b border-white/5 sticky top-0 z-40">
                <div class="font-outfit font-bold text-lg">Cyber<span class="text-blue-500">Sec</span></div>
                <div class="flex items-center gap-3">
                    <div class="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center font-bold text-white uppercase text-sm" x-text="username ? username.charAt(0) : 'U'"></div>
                    <button @click="sidebarOpen = !sidebarOpen" class="text-gray-300 hover:text-white">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path></svg>
                    </button>
                </div>
            </header>

            <div class="p-6 md:p-10 max-w-7xl mx-auto">
                @yield('content')
            </div>
        </main>
    </div>

    <script>
        document.addEventListener('alpine:init', () => {
            Alpine.data('appLayout', () => ({
                sidebarOpen: false,
                username: '',
                init() {
                    // Cek token tiap masuk page yang pakai layout ini
                    if(!localStorage.getItem('access_token')) {
                        window.location.href = '/login';
                    }
                    this.username = localStorage.getItem('username') || '';
                },
                isRoute(path) {
                    return window.location.pathname === path;
                },
                logout() {
                    Swal.fire({
                        title: 'Logout?',
                        text: "Anda akan keluar dari sesi ini.",
                        icon: 'warning',
                        showCancelButton: true,
                        confirmButtonColor: '#3b82f6',
                        cancelButtonColor: '#ef4444',
                        confirmButtonText: 'Ya, Logout'
                    }).then((result) => {
                        if (result.isConfirmed) {
                            window.api.logout();
                        }
                    })
                }
            }));
        });
    </script>
    @stack('scripts')
</body>
</html>
