@extends('layouts.app')

@section('content')
<div x-data="attacksCtrl()">
    <div class="mb-8">
        <h1 class="text-3xl font-outfit font-bold mb-2">Attacks Reference</h1>
        <p class="text-gray-400">Database of known attack vectors and their symptoms.</p>
    </div>

    <template x-if="isLoading">
        <div class="py-12 flex justify-center items-center">
            <svg class="animate-spin h-8 w-8 text-blue-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
        </div>
    </template>

    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <template x-for="attack in attacks" :key="attack.id">
            <div class="glass-panel flex flex-col h-full">
                <div class="flex justify-between items-start mb-4">
                    <h3 class="text-lg font-bold text-blue-400" x-text="attack.attack_type"></h3>
                    <span class="px-2 py-1 text-xs font-bold rounded-md bg-white/5 border border-white/10 text-gray-300" x-text="'MITRE: ' + attack.mitre_id"></span>
                </div>
                
                <div class="mb-4 flex-1">
                    <h4 class="text-xs text-gray-500 uppercase tracking-wider mb-2">Severity</h4>
                    <span class="px-3 py-1 text-xs font-bold rounded-full capitalize"
                          :class="{
                              'bg-red-500/20 text-red-400 border border-red-500/30': attack.severity === 'critical',
                              'bg-orange-500/20 text-orange-400 border border-orange-500/30': attack.severity === 'high',
                              'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30': attack.severity === 'medium',
                              'bg-blue-500/20 text-blue-400 border border-blue-500/30': attack.severity === 'low'
                          }" x-text="attack.severity"></span>
                </div>

                <div>
                    <h4 class="text-xs text-gray-500 uppercase tracking-wider mb-2">Symptoms</h4>
                    <div class="flex flex-wrap gap-2">
                        <template x-for="symptom in attack.symptoms">
                            <span class="px-2 py-1 bg-white/5 text-gray-300 rounded text-xs" x-text="symptom.replace(/_/g, ' ')"></span>
                        </template>
                    </div>
                </div>
            </div>
        </template>
    </div>
</div>
@endsection

@push('scripts')
<script>
document.addEventListener('alpine:init', () => {
    Alpine.data('attacksCtrl', () => ({
        isLoading: true,
        attacks: [],
        
        async init() {
            try {
                this.attacks = await window.api.getAttacks();
            } catch(e) {
                Swal.fire({icon: 'error', title: 'Failed to load attacks', text: e.message, background: '#1e293b', color: '#fff'});
            } finally {
                this.isLoading = false;
            }
        }
    }));
});
</script>
@endpush
