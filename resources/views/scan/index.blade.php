@extends('layouts.app')

@section('content')
<div x-data="scanPage()" class="space-y-6">
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-3xl font-outfit font-bold text-white">Active Scanner</h1>
            <p class="text-gray-400 mt-1">Lakukan pemindaian otomatis pada URL target untuk mendeteksi kerentanan.</p>
        </div>
    </div>

    <!-- Form Section -->
    <div class="bg-slate-900/50 backdrop-blur border border-white/10 rounded-2xl p-6 md:p-10" x-show="!result && !loading">
        <div class="max-w-2xl mx-auto text-center">
            <div class="w-16 h-16 bg-blue-500/20 text-blue-500 rounded-2xl flex items-center justify-center mx-auto mb-6">
                <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
            </div>
            <h2 class="text-2xl font-bold text-white mb-2">Target URL</h2>
            <p class="text-gray-400 mb-8">Masukkan URL lengkap dari aplikasi yang ingin Anda pindai. Pastikan Anda memiliki izin untuk memindai target tersebut.</p>

            <form @submit.prevent="startScan" class="relative">
                <div class="relative flex items-center">
                    <div class="absolute left-4 text-gray-500">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                    </div>
                    <input type="url" x-model="url" required placeholder="https://example.com" class="w-full bg-slate-800/50 border border-white/10 rounded-xl py-4 pl-12 pr-32 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all placeholder-gray-600 font-mono">
                    <button type="submit" class="absolute right-2 top-2 bottom-2 px-6 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium transition-colors shadow-lg disabled:opacity-50" :disabled="!url">
                        Scan
                    </button>
                </div>
            </form>
            
            <div class="mt-6 p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-start gap-3 text-left">
                <svg class="w-5 h-5 text-amber-500 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                <div class="text-sm text-amber-200/80">
                    <strong class="text-amber-400 block mb-1">Peringatan Penggunaan</strong>
                    Fitur ini akan secara aktif mengirimkan payload uji coba ke server target. Proses ini mungkin memakan waktu 3-30 detik. Rate limit diberlakukan (5 request/menit).
                </div>
            </div>
        </div>
    </div>

    <!-- Loading State -->
    <div x-show="loading" class="bg-slate-900/50 backdrop-blur border border-white/10 rounded-2xl p-10 text-center" style="display: none;">
        <div class="relative w-32 h-32 mx-auto mb-8">
            <!-- Pulsing rings -->
            <div class="absolute inset-0 bg-blue-500/20 rounded-full animate-ping"></div>
            <div class="absolute inset-2 bg-blue-500/20 rounded-full animate-ping" style="animation-delay: 0.2s"></div>
            <!-- Center radar -->
            <div class="absolute inset-0 border-2 border-blue-500/30 rounded-full"></div>
            <div class="absolute inset-0 rounded-full border-t-2 border-r-2 border-blue-500 animate-spin"></div>
            <div class="absolute inset-0 flex items-center justify-center">
                <svg class="w-8 h-8 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
            </div>
        </div>
        <h3 class="text-2xl font-bold text-white mb-2">Memindai Target</h3>
        <p class="text-blue-400 font-mono text-sm mb-4" x-text="url"></p>
        <div class="max-w-md mx-auto text-gray-400 text-sm">
            <p class="animate-pulse">Sedang mengekstrak gejala dan menguji kerentanan...</p>
            <p class="mt-2 text-xs">Harap tunggu, proses ini mungkin memakan waktu hingga 30 detik.</p>
        </div>
    </div>

    <!-- Result Section -->
    <div x-show="result" style="display: none;" class="space-y-6">
        <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center bg-slate-900/50 border border-white/10 rounded-xl p-4 gap-4">
            <div>
                <p class="text-sm text-gray-400">Target Scan</p>
                <p class="font-mono text-blue-400" x-text="url"></p>
            </div>
            <div class="flex items-center gap-3">
                <span class="text-sm text-gray-400" x-text="result?.analysis_duration_ms ? `Selesai dalam ${(result.analysis_duration_ms/1000).toFixed(1)}s` : ''"></span>
                <button @click="reset()" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors">
                    Scan Baru
                </button>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <!-- Attacks -->
            <div class="bg-slate-900/50 border border-red-500/20 rounded-2xl p-6">
                <h3 class="text-lg font-bold text-red-400 mb-4 flex items-center gap-2">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                    Kerentanan Ditemukan
                </h3>
                <div class="space-y-4">
                    <template x-if="result?.detected_attacks?.length === 0">
                        <div class="p-6 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-center">
                            <svg class="w-12 h-12 text-emerald-500 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                            <p class="text-emerald-400 font-medium">Tidak ada kerentanan tinggi yang terdeteksi.</p>
                        </div>
                    </template>
                    <template x-for="attack in result?.detected_attacks" :key="attack.attack_type">
                        <div class="bg-red-500/5 border border-red-500/10 p-4 rounded-xl">
                            <div class="flex justify-between items-start mb-2">
                                <h4 class="font-bold text-white" x-text="attack.attack_type"></h4>
                                <span class="px-2 py-1 bg-red-500/20 text-red-400 text-xs rounded font-bold" x-text="(attack.confidence * 100).toFixed(1) + '%'"></span>
                            </div>
                            <p class="text-sm text-gray-300 mb-2" x-text="attack.description"></p>
                            <div class="text-xs text-gray-500 font-mono" x-text="'MITRE: ' + attack.mitre_id"></div>
                        </div>
                    </template>
                </div>
            </div>

            <!-- Recommendations -->
            <div class="bg-slate-900/50 border border-blue-500/20 rounded-2xl p-6">
                <h3 class="text-lg font-bold text-blue-400 mb-4 flex items-center gap-2">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    Saran Mitigasi
                </h3>
                <div class="space-y-4">
                    <template x-if="result?.defense_recommendations?.length === 0">
                        <p class="text-gray-400">Tidak ada rekomendasi khusus saat ini.</p>
                    </template>
                    <template x-for="rec in result?.defense_recommendations" :key="rec.action">
                        <div class="flex gap-4 bg-white/5 p-4 rounded-xl">
                            <div class="flex-shrink-0 w-8 h-8 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center font-bold" x-text="rec.priority"></div>
                            <div>
                                <p class="text-gray-200 text-sm font-medium" x-text="rec.action"></p>
                                <p class="text-xs text-blue-400 mt-1" x-text="'Tools: ' + rec.tool_suggestion"></p>
                            </div>
                        </div>
                    </template>
                </div>
            </div>
        </div>
    </div>
</div>

@push('scripts')
<script>
document.addEventListener('alpine:init', () => {
    Alpine.data('scanPage', () => ({
        url: '',
        loading: false,
        result: null,
        async startScan() {
            if (!this.url) return;
            
            // Basic URL validation
            try {
                new URL(this.url);
            } catch (e) {
                Swal.fire({
                    icon: 'error',
                    title: 'URL Tidak Valid',
                    text: 'Pastikan URL diawali dengan http:// atau https://',
                    background: '#1e293b',
                    color: '#fff',
                    confirmButtonColor: '#3b82f6'
                });
                return;
            }

            this.loading = true;
            this.result = null;
            try {
                this.result = await window.api.scan(this.url);
            } catch (error) {
                Swal.fire({
                    icon: 'error',
                    title: 'Scan Gagal',
                    text: error.message || 'Terjadi kesalahan saat memindai target.',
                    background: '#1e293b',
                    color: '#fff',
                    confirmButtonColor: '#3b82f6'
                });
            } finally {
                this.loading = false;
            }
        },
        reset() {
            this.result = null;
            this.url = '';
        }
    }));
});
</script>
@endpush
@endsection
