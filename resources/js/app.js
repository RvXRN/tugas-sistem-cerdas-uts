import Alpine from 'alpinejs';
import Chart from 'chart.js/auto';
import Swal from 'sweetalert2';

window.Alpine = Alpine;
window.Chart = Chart;
window.Swal = Swal;

const API_URL = import.meta.env.VITE_API_BASE_URL || 'https://api-cysec.bilikku.my.id/api/v1';

window.api = {
    getHeaders(isJson = true) {
        const token = localStorage.getItem('access_token');
        const headers = {};
        if (isJson) headers['Content-Type'] = 'application/json';
        if (token) headers['Authorization'] = `Bearer ${token}`;
        return headers;
    },

    async request(endpoint, options = {}) {
        try {
            const response = await fetch(`${API_URL}${endpoint}`, options);
            if (response.status === 401) {
                localStorage.removeItem('access_token');
                localStorage.removeItem('username');
                
                // Jika sedang tidak di halaman login, tampilkan alert
                if (window.location.pathname !== '/login') {
                    await Swal.fire({
                        icon: 'warning',
                        title: 'Sesi Kedaluwarsa',
                        text: 'Token Anda telah habis masa berlakunya. Silakan login kembali.',
                        background: '#1e293b',
                        color: '#fff',
                        confirmButtonColor: '#3b82f6'
                    });
                    window.location.href = '/login';
                }
                return null;
            }
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.detail || data.message || 'Terjadi kesalahan pada server.');
            }
            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },

    async login(username, password, rememberMe = false) {
        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('password', password);
        if (rememberMe) {
            formData.append('remember_me', 'true');
        }

        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: formData.toString()
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Login gagal.');
        
        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('username', username); // Save username for UI
        return data;
    },

    async register(username, email, password) {
        return this.request('/auth/register', {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({ username, email, password })
        });
    },

    async detect(symptoms) {
        return this.request('/detect', {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({ symptoms })
        });
    },

    async scan(url) {
        return this.request('/scan', {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({ url })
        });
    },

    async getAttacks() {
        return this.request('/attacks/', {
            method: 'GET',
            headers: this.getHeaders()
        });
    },

    async getHistory() {
        return this.request('/history/', {
            method: 'GET',
            headers: this.getHeaders()
        });
    },

    async getDatasetStats() {
        return this.request('/datasets/stats', {
            method: 'GET',
            headers: this.getHeaders()
        });
    },

    async loadDatasets() {
        return this.request('/datasets/load', {
            method: 'POST',
            headers: this.getHeaders()
        });
    },

    logout() {
        localStorage.removeItem('access_token');
        window.location.href = '/login';
    }
};

Alpine.start();
