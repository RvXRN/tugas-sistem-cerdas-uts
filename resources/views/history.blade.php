@extends('layouts.app')

@section('content')
<div x-data="historyCtrl()">
    <div class="mb-8">
        <h1 class="text-3xl font-outfit font-bold mb-2">Consultation History</h1>
        <p class="text-gray-400">View your past detections and scans.</p>
    </div>

    <div class="glass-panel">
        <template x-if="isLoading">
            <div class="py-12 flex justify-center items-center">
                <svg class="animate-spin h-8 w-8 text-blue-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
            </div>
        </template>
        
        <template x-if="!isLoading && (!historyData || historyData.length === 0)">
            <div class="py-12 text-center text-gray-500">
                <p>No history available yet.</p>
                <p class="text-sm mt-2" x-text="message"></p>
            </div>
        </template>

        <template x-if="!isLoading && historyData && historyData.length > 0">
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="border-b border-white/5">
                            <th class="p-4 text-gray-400 font-medium text-sm tracking-wider uppercase">Date</th>
                            <th class="p-4 text-gray-400 font-medium text-sm tracking-wider uppercase">Type</th>
                            <th class="p-4 text-gray-400 font-medium text-sm tracking-wider uppercase">Findings</th>
                        </tr>
                    </thead>
                    <tbody>
                        <template x-for="(item, index) in historyData" :key="index">
                            <tr class="border-b border-white/5 hover:bg-white/5 transition-colors">
                                <td class="p-4 text-gray-300 text-sm font-medium">
                                    <span x-text="item.date || item.created_at ? new Date(item.date || item.created_at).toLocaleString() : 'Recent'"></span>
                                </td>
                                <td class="p-4">
                                    <span class="px-3 py-1 text-xs font-bold rounded-full capitalize"
                                          :class="(item.type || '').toLowerCase() === 'scan' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'"
                                          x-text="item.type || 'Detection'"></span>
                                </td>
                                <td class="p-4">
                                    <template x-if="item.detected_attacks && item.detected_attacks.length > 0">
                                        <div class="flex flex-wrap gap-2">
                                            <template x-for="(attack, i) in item.detected_attacks">
                                                <template x-if="i < 2">
                                                    <span class="px-2 py-1 text-xs font-medium rounded bg-red-500/20 text-red-400 border border-red-500/20" x-text="typeof attack === 'string' ? attack : attack.attack_type"></span>
                                                </template>
                                            </template>
                                            <template x-if="item.detected_attacks.length > 2">
                                                <span class="px-2 py-1 text-xs font-medium rounded bg-gray-500/20 text-gray-400 border border-gray-500/20" x-text="'+' + (item.detected_attacks.length - 2) + ' more'"></span>
                                            </template>
                                        </div>
                                    </template>
                                    <template x-if="!item.detected_attacks || item.detected_attacks.length === 0">
                                        <span class="text-gray-500 text-sm flex items-center gap-1">
                                            <svg class="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                                            Safe (No threats)
                                        </span>
                                    </template>
                                </td>
                            </tr>
                        </template>
                    </tbody>
                </table>
            </div>
        </template>
    </div>
</div>
@endsection

@push('scripts')
<script>
document.addEventListener('alpine:init', () => {
    Alpine.data('historyCtrl', () => ({
        isLoading: true,
        historyData: [],
        message: '',
        
        async init() {
            try {
                const res = await window.api.getHistory();
                this.message = res.message || '';
                this.historyData = res.data || [];
            } catch(e) {
                Swal.fire({icon: 'error', title: 'Failed to load history', text: e.message, background: '#1e293b', color: '#fff'});
            } finally {
                this.isLoading = false;
            }
        }
    }));
});
</script>
@endpush
