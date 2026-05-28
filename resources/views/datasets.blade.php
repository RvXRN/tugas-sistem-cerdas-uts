@extends('layouts.app')

@section('content')
<div x-data="datasetCtrl()">
    <div class="mb-8">
        <h1 class="text-3xl font-outfit font-bold mb-2">Dataset Management</h1>
        <p class="text-gray-400">View dataset statistics and reload database records.</p>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <!-- Chart Section -->
        <div class="glass-panel">
            <div class="flex justify-between items-center mb-6">
                <h3 class="text-xl font-bold flex items-center gap-2">
                    <svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.488 9H15V3.512A9.025 9.025 0 0120.488 9z"></path></svg>
                    Statistics
                </h3>
                <button @click="loadStats" class="text-blue-400 hover:text-blue-300 transition-colors" title="Refresh Stats">
                    <svg class="w-5 h-5" :class="{'animate-spin': isLoadingStats}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                </button>
            </div>
            
            <div class="relative h-64 flex justify-center items-center">
                <template x-if="isLoadingStats">
                    <svg class="animate-spin h-8 w-8 text-blue-500 absolute" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                </template>
                <canvas id="statsChart" class="w-full h-full" :class="{'opacity-0': isLoadingStats}"></canvas>
            </div>
        </div>

        <!-- Operations Section -->
        <div class="glass-panel">
            <h3 class="text-xl font-bold mb-6 flex items-center gap-2">
                <svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path></svg>
                Data Operations
            </h3>
            
            <p class="text-gray-400 text-sm mb-6">
                Reload dataset from the latest CSV sources into the database. This operation may take some time depending on the dataset size.
            </p>

            <button @click="loadDatasets" :disabled="isReloading" class="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-4 px-4 rounded-lg transition-all flex justify-center items-center gap-2 shadow-[0_0_15px_rgba(16,185,129,0.3)] hover:shadow-[0_0_25px_rgba(16,185,129,0.5)]">
                <template x-if="isReloading">
                    <svg class="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                </template>
                <span x-text="isReloading ? 'Reloading Datasets...' : 'Reload Datasets from CSV'"></span>
            </button>
            
            <div x-show="reloadResult" class="mt-6 bg-white/5 border border-white/10 p-4 rounded-lg text-sm" style="display: none;">
                <p class="text-emerald-400 font-bold mb-2" x-text="reloadResult?.message"></p>
                <ul class="text-gray-300 space-y-1">
                    <li>Threat Intel: <span x-text="reloadResult?.data?.threat_intel_loaded"></span></li>
                    <li>CVEs: <span x-text="reloadResult?.data?.cves_loaded"></span></li>
                    <li>IOCs: <span x-text="reloadResult?.data?.iocs_loaded"></span></li>
                    <li class="pt-2 mt-2 border-t border-white/10 font-bold">Total: <span x-text="reloadResult?.data?.total_loaded"></span></li>
                </ul>
            </div>
        </div>
    </div>
</div>
@endsection

@push('scripts')
<script>
document.addEventListener('alpine:init', () => {
    Alpine.data('datasetCtrl', () => ({
        isLoadingStats: true,
        isReloading: false,
        chartInstance: null,
        reloadResult: null,
        
        async init() {
            await this.loadStats();
        },

        async loadStats() {
            this.isLoadingStats = true;
            try {
                const res = await window.api.getDatasetStats();
                this.renderChart(res);
            } catch(e) {
                Swal.fire({icon: 'error', title: 'Failed to load stats', text: e.message, background: '#1e293b', color: '#fff'});
            } finally {
                this.isLoadingStats = false;
            }
        },

        renderChart(data) {
            const ctx = document.getElementById('statsChart');
            if(this.chartInstance) {
                this.chartInstance.destroy();
            }
            
            // Mengatur default font ChartJS menyesuaikan Tailwind
            Chart.defaults.color = '#9ca3af';
            Chart.defaults.font.family = "'Inter', sans-serif";

            this.chartInstance = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Threat Intel', 'CVEs', 'IOCs'],
                    datasets: [{
                        data: [data.threat_intel || 0, data.cves || 0, data.iocs || 0],
                        backgroundColor: [
                            'rgba(59, 130, 246, 0.8)', // blue-500
                            'rgba(16, 185, 129, 0.8)', // emerald-500
                            'rgba(245, 158, 11, 0.8)'  // amber-500
                        ],
                        borderColor: '#0b0f19',
                        borderWidth: 2,
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { padding: 20, usePointStyle: true }
                        }
                    },
                    cutout: '70%'
                }
            });
        },

        async loadDatasets() {
            // Confirm first
            const confirm = await Swal.fire({
                title: 'Are you sure?',
                text: "This will reload datasets from CSV into the database.",
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#10b981',
                cancelButtonColor: '#ef4444',
                confirmButtonText: 'Yes, reload it!',
                background: '#1e293b',
                color: '#fff'
            });

            if (!confirm.isConfirmed) return;

            this.isReloading = true;
            this.reloadResult = null;
            
            // Tampilkan SweetAlert Loading State
            Swal.fire({
                title: 'Loading Datasets',
                html: 'Please wait while records are imported...',
                allowOutsideClick: false,
                background: '#1e293b',
                color: '#fff',
                didOpen: () => {
                    Swal.showLoading();
                }
            });

            try {
                const res = await window.api.loadDatasets();
                this.reloadResult = res;
                Swal.fire({
                    icon: 'success',
                    title: 'Datasets Reloaded!',
                    text: res.message,
                    background: '#1e293b',
                    color: '#fff'
                });
                // Refresh chart with new stats
                await this.loadStats();
            } catch(e) {
                Swal.fire({icon: 'error', title: 'Failed to reload', text: e.message, background: '#1e293b', color: '#fff'});
            } finally {
                this.isReloading = false;
            }
        }
    }));
});
</script>
@endpush
