@extends('layouts.app')

@section('content')
<div x-data="dashboardCtrl()">
    <div class="mb-8">
        <h1 class="text-3xl font-outfit font-bold mb-2">Dashboard Center</h1>
        <p class="text-gray-400">Perform manual symptom analysis or active URL scanning.</p>
    </div>

    <!-- Tabs -->
    <div class="flex space-x-1 bg-slate-900/50 p-1 rounded-xl mb-8 border border-white/5 w-fit">
        <button @click="tab = 'manual'" :class="tab === 'manual' ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'" class="px-6 py-2.5 rounded-lg text-sm font-medium transition-all duration-300">
            Manual Detection
        </button>
        <button @click="tab = 'scan'" :class="tab === 'scan' ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-500/20' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'" class="px-6 py-2.5 rounded-lg text-sm font-medium transition-all duration-300">
            Active Scanner
        </button>
    </div>

    <!-- Manual Detection Tab -->
    <div x-show="tab === 'manual'" x-transition:enter="transition ease-out duration-300" x-transition:enter-start="opacity-0 translate-y-4" x-transition:enter-end="opacity-100 translate-y-0" style="display: none;">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div class="glass-panel">
                <h3 class="text-xl font-bold mb-6 flex items-center gap-2">
                    <svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    Submit Symptoms
                </h3>
                <form @submit.prevent="detect" class="space-y-5">
                    <div>
                        <label class="block text-sm text-gray-400 mb-2">Select Symptoms (Hold Ctrl/Cmd to select multiple)</label>
                        <select multiple x-model="selectedSymptoms" class="input-control h-48 py-2">
                            <optgroup label="Reconnaissance">
                                <option value="port_scanning">Port Scanning</option>
                                <option value="os_fingerprinting">OS Fingerprinting</option>
                                <option value="banner_grabbing">Banner Grabbing</option>
                            </optgroup>
                            <optgroup label="Brute Force">
                                <option value="brute_force_login">Brute Force Login</option>
                                <option value="multiple_failed_auth">Multiple Failed Auth</option>
                                <option value="credential_stuffing">Credential Stuffing</option>
                            </optgroup>
                            <optgroup label="SQL Injection">
                                <option value="sql_injection_pattern">SQL Injection Pattern</option>
                                <option value="error_based_response">Error Based Response</option>
                            </optgroup>
                            <optgroup label="XSS & Web">
                                <option value="xss_payload_detected">XSS Payload Detected</option>
                                <option value="script_tag_in_input">Script Tag in Input</option>
                            </optgroup>
                        </select>
                        <p class="text-xs text-gray-500 mt-2">Selected: <span x-text="selectedSymptoms.length"></span> symptoms</p>
                    </div>

                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target System</label>
                            <select x-model="targetSystem" class="input-control">
                                <option value="">Auto-detect</option>
                                <option value="web_server">Web Server</option>
                                <option value="database">Database</option>
                                <option value="network">Network</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Severity Hint</label>
                            <select x-model="severityHint" class="input-control">
                                <option value="">Unknown</option>
                                <option value="low">Low</option>
                                <option value="medium">Medium</option>
                                <option value="high">High</option>
                                <option value="critical">Critical</option>
                            </select>
                        </div>
                    </div>

                    <button type="submit" :disabled="isDetecting" class="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-3 px-4 rounded-lg transition-all flex justify-center items-center gap-2">
                        <span x-text="isDetecting ? 'Analyzing...' : 'Run Detection'"></span>
                    </button>
                </form>
            </div>

            <!-- Results -->
            <div x-show="detectResult" class="glass-panel" style="display: none;">
                <div class="flex justify-between items-center mb-6">
                    <h3 class="text-xl font-bold text-green-400">Analysis Complete</h3>
                    <span x-show="detectResult?.from_cache" class="bg-purple-500/20 text-purple-400 px-3 py-1 rounded-full text-xs font-bold border border-purple-500/30">Cached</span>
                </div>
                
                <div class="space-y-6">
                    <div>
                        <h4 class="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">Detected Attacks</h4>
                        <template x-for="attack in detectResult?.detected_attacks">
                            <div class="bg-red-500/10 border border-red-500/20 p-4 rounded-lg mb-3">
                                <div class="flex justify-between mb-2">
                                    <strong class="text-red-400" x-text="attack.attack_type"></strong>
                                    <span class="text-sm text-gray-400" x-text="(attack.confidence * 100).toFixed(1) + '% Confidence'"></span>
                                </div>
                                <p class="text-sm text-gray-300" x-text="attack.description"></p>
                                <p class="text-xs text-red-300/70 mt-2">MITRE ID: <span x-text="attack.mitre_id"></span></p>
                            </div>
                        </template>
                        <div x-show="!detectResult?.detected_attacks?.length" class="text-gray-400 text-sm">No threats detected.</div>
                    </div>

                    <div>
                        <h4 class="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">Recommendations</h4>
                        <ul class="space-y-2">
                            <template x-for="rec in detectResult?.defense_recommendations">
                                <li class="flex gap-3 bg-white/5 p-3 rounded-lg border border-white/5">
                                    <span class="text-blue-400 font-bold" x-text="'P'+rec.priority"></span>
                                    <div>
                                        <p class="text-sm text-gray-200" x-text="rec.action"></p>
                                        <p class="text-xs text-gray-500" x-text="'Tools: ' + rec.tool_suggestion"></p>
                                    </div>
                                </li>
                            </template>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Active Scanner Tab -->
    <div x-show="tab === 'scan'" x-transition:enter="transition ease-out duration-300" x-transition:enter-start="opacity-0 translate-y-4" x-transition:enter-end="opacity-100 translate-y-0" style="display: none;">
        <div class="glass-panel max-w-2xl mx-auto">
            <h3 class="text-xl font-bold mb-2 flex items-center gap-2">
                <svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                Active Scanner
            </h3>
            <p class="text-sm text-gray-400 mb-6">Scan your web application for vulnerabilities. Limit: 5 requests/minute.</p>
            
            <form @submit.prevent="scan" class="space-y-4">
                <div>
                    <input type="url" x-model="scanUrl" required class="input-control text-lg py-4" placeholder="https://your-target.com/">
                </div>
                
                <button type="submit" :disabled="isScanning" class="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-4 px-4 rounded-lg transition-all flex justify-center items-center gap-2 text-lg">
                    <template x-if="isScanning">
                        <svg class="animate-spin h-6 w-6 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    </template>
                    <span x-text="isScanning ? 'Scanning Target (Takes 3-30s)...' : 'Start Scan'"></span>
                </button>
            </form>
        </div>
    </div>
</div>
@endsection

@push('scripts')
<script>
document.addEventListener('alpine:init', () => {
    Alpine.data('dashboardCtrl', () => ({
        tab: 'manual',
        selectedSymptoms: [],
        targetSystem: '',
        severityHint: '',
        isDetecting: false,
        detectResult: null,
        
        scanUrl: '',
        isScanning: false,

        async detect() {
            if(this.selectedSymptoms.length === 0) {
                Swal.fire({icon: 'warning', title: 'Oops', text: 'Select at least one symptom.', background: '#1e293b', color: '#fff'});
                return;
            }
            this.isDetecting = true;
            this.detectResult = null;
            try {
                const res = await window.api.detect(this.selectedSymptoms, this.targetSystem, this.severityHint);
                this.detectResult = res;
                Swal.fire({
                    toast: true,
                    position: 'top-end',
                    icon: 'success',
                    title: `Analysis took ${res.analysis_duration_ms}ms`,
                    showConfirmButton: false,
                    timer: 3000,
                    background: '#1e293b',
                    color: '#fff'
                });
            } catch(e) {
                Swal.fire({icon: 'error', title: 'Error', text: e.message, background: '#1e293b', color: '#fff'});
            } finally {
                this.isDetecting = false;
            }
        },

        async scan() {
            if(!this.scanUrl) return;
            this.isScanning = true;
            try {
                const res = await window.api.scan(this.scanUrl);
                this.detectResult = res;
                this.tab = 'manual'; // switch to results view
                Swal.fire({
                    icon: 'success',
                    title: 'Scan Complete',
                    text: `Found ${res.detected_attacks?.length || 0} vulnerabilities.`,
                    background: '#1e293b',
                    color: '#fff'
                });
            } catch(e) {
                Swal.fire({icon: 'error', title: 'Scan Failed', text: e.message, background: '#1e293b', color: '#fff'});
            } finally {
                this.isScanning = false;
            }
        }
    }));
});
</script>
@endpush
