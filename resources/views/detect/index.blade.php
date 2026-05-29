@extends('layouts.app')

@section('content')
<div x-data="detectPage()" class="space-y-6">
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-3xl font-outfit font-bold text-white">Manual Detection</h1>
            <p class="text-gray-400 mt-1">Pilih gejala yang Anda temukan pada log atau sistem untuk mendiagnosis serangan.</p>
        </div>
    </div>

    <!-- Form Section -->
    <div class="bg-slate-900/50 backdrop-blur border border-white/10 rounded-2xl p-6" x-show="!result && !loading">
        <form @submit.prevent="submitDetect">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6 mb-8">
                <template x-for="(group, category) in symptomGroups" :key="category">
                    <div class="space-y-3">
                        <h3 class="text-sm font-bold text-blue-400 uppercase tracking-wider" x-text="category"></h3>
                        <div class="space-y-2">
                            <template x-for="symptom in group" :key="symptom">
                                <label class="flex items-center gap-3 p-2 rounded-lg hover:bg-white/5 cursor-pointer transition-colors border border-transparent hover:border-white/10"
                                       :class="symptoms.includes(symptom) ? 'bg-blue-500/10 border-blue-500/30' : ''">
                                    <input type="checkbox" :value="symptom" x-model="symptoms" class="w-4 h-4 rounded border-gray-600 text-blue-500 focus:ring-blue-500 focus:ring-offset-gray-900 bg-gray-800">
                                    <span class="text-sm text-gray-300" x-text="formatSymptom(symptom)"></span>
                                </label>
                            </template>
                        </div>
                    </div>
                </template>
            </div>

            <div class="flex justify-end">
                <button type="submit" class="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-medium transition-all shadow-[0_0_20px_rgba(37,99,235,0.3)] hover:shadow-[0_0_25px_rgba(37,99,235,0.5)] flex items-center gap-2" :disabled="symptoms.length === 0" :class="{'opacity-50 cursor-not-allowed': symptoms.length === 0}">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>
                    Jalankan Analisis
                </button>
            </div>
        </form>
    </div>

    <!-- Loading State -->
    <div x-show="loading" class="flex flex-col items-center justify-center py-20" style="display: none;">
        <div class="relative w-24 h-24">
            <div class="absolute inset-0 border-4 border-blue-500/20 rounded-full"></div>
            <div class="absolute inset-0 border-4 border-blue-500 rounded-full border-t-transparent animate-spin"></div>
        </div>
        <h3 class="text-xl font-bold mt-6 text-white animate-pulse">Menganalisis Gejala...</h3>
        <p class="text-gray-400 mt-2">Sistem pakar sedang memproses data Anda.</p>
    </div>

    <!-- Result Section -->
    <div x-show="result" style="display: none;" class="space-y-6">
        <div class="flex justify-between items-center bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-4">
            <div class="flex items-center gap-3 text-emerald-400">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                <span class="font-medium">Analisis Selesai</span>
            </div>
            <button @click="reset()" class="px-4 py-2 bg-white/5 hover:bg-white/10 rounded-lg text-sm font-medium transition-colors">
                Analisis Baru
            </button>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <!-- Attacks -->
            <div class="bg-slate-900/50 border border-red-500/20 rounded-2xl p-6">
                <h3 class="text-lg font-bold text-red-400 mb-4 flex items-center gap-2">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                    Potensi Serangan
                </h3>
                <div class="space-y-4">
                    <template x-if="result?.detected_attacks?.length === 0">
                        <p class="text-gray-400">Tidak ada serangan signifikan yang terdeteksi.</p>
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
                    Rekomendasi Pertahanan
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
    Alpine.data('detectPage', () => ({
        symptoms: [],
        loading: false,
        result: null,
        symptomGroups: {
            'Reconnaissance': ['port_scanning', 'os_fingerprinting', 'service_enumeration', 'banner_grabbing', 'network_mapping', 'ping_sweep', 'dns_enumeration', 'whois_lookup', 'traceroute_activity', 'idle_scan', 'version_detection', 'tcp_connect_scan'],
            'Brute Force Attack': ['brute_force_login', 'multiple_failed_auth', 'high_login_attempts', 'credential_stuffing', 'password_spraying', 'dictionary_attack', 'account_lockout_triggered', 'rapid_auth_requests', 'failed_ssh_attempts', 'failed_rdp_attempts', 'auth_log_flooding'],
            'SQL Injection': ['sql_injection_pattern', 'unusual_db_query', 'error_based_response', 'blind_sqli_timing', 'union_based_payload', 'stacked_queries', 'out_of_band_sqli', 'db_error_in_response', 'tautology_in_query', 'encoded_sql_payload', 'time_delay_response', 'boolean_blind_sqli'],
            'DDoS': ['high_traffic_volume', 'service_degradation', 'syn_flood', 'udp_flood', 'http_flood', 'amplification_traffic', 'icmp_flood', 'slow_loris_attack', 'bandwidth_saturation', 'connection_exhaustion', 'dns_amplification', 'ntp_amplification'],
            'XSS': ['xss_payload_detected', 'script_tag_in_input', 'dom_manipulation', 'cookie_theft_attempt', 'reflected_payload', 'stored_xss_payload', 'event_handler_injection', 'javascript_uri_injection', 'malicious_iframe_injection', 'html_entity_bypass', 'csp_bypass_attempt'],
            'MitM': ['arp_spoofing', 'ssl_stripping', 'certificate_anomaly', 'dns_spoofing', 'unusual_gateway_mac', 'rogue_dhcp_server', 'packet_interception', 'session_hijacking', 'ssl_certificate_mismatch', 'bgp_hijacking', 'evil_twin_ap', 'ip_spoofing'],
            'Phishing': ['suspicious_email_link', 'domain_spoofing', 'credential_harvesting', 'fake_login_page', 'email_header_anomaly', 'lookalike_domain', 'urgency_in_email', 'malicious_attachment', 'brand_impersonation', 'spear_phishing_indicators', 'whaling_attempt', 'vishing_indicators'],
            'Ransomware': ['mass_file_encryption', 'ransom_note_created', 'shadow_copy_deletion', 'unusual_file_extension', 'c2_communication', 'file_rename_burst', 'backup_deletion', 'registry_modification', 'process_injection', 'lateral_movement', 'data_exfiltration_before_encryption', 'bitcoin_address_in_note']
        },
        formatSymptom(str) {
            return str.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
        },
        async submitDetect() {
            if (this.symptoms.length === 0) return;
            this.loading = true;
            this.result = null;
            try {
                this.result = await window.api.detect(this.symptoms);
            } catch (error) {
                Swal.fire({
                    icon: 'error',
                    title: 'Gagal',
                    text: error.message || 'Terjadi kesalahan saat deteksi.',
                    background: '#1e293b',
                    color: '#fff',
                    confirmButtonColor: '#3b82f6'
                });
            } finally {
                this.loading = false;
            }
        },
        reset() {
            this.symptoms = [];
            this.result = null;
        }
    }));
});
</script>
@endpush
@endsection
