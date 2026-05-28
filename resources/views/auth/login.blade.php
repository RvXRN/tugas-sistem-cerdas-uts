<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | CyberSec</title>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body class="bg-gray-950 text-gray-100 font-inter antialiased flex items-center justify-center min-h-screen relative">
    
    <!-- Decor blobs -->
    <div class="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-600/20 rounded-full blur-[100px] pointer-events-none"></div>
    <div class="absolute bottom-1/4 right-1/4 w-96 h-96 bg-emerald-600/20 rounded-full blur-[100px] pointer-events-none"></div>

    <div class="glass-panel w-full max-w-md mx-4 relative z-10 p-8">
        <div class="text-center mb-8">
            <h1 class="text-3xl font-outfit font-bold mb-2">Welcome Back</h1>
            <p class="text-gray-400">Login to access the CyberSec Dashboard.</p>
        </div>

        <form x-data="loginForm()" @submit.prevent="submit" class="space-y-5">
            <div>
                <label class="block text-sm text-gray-400 mb-2">Username</label>
                <input type="text" x-model="username" required 
                       class="input-control" placeholder="Enter username">
            </div>
            
            <div>
                <label class="block text-sm text-gray-400 mb-2">Password</label>
                <input type="password" x-model="password" required 
                       class="input-control" placeholder="Enter password">
            </div>

            <button type="submit" :disabled="isLoading" 
                    class="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-3 px-4 rounded-lg transition-all duration-300 shadow-[0_0_15px_rgba(37,99,235,0.4)] hover:shadow-[0_0_25px_rgba(37,99,235,0.6)] flex items-center justify-center gap-2">
                <template x-if="isLoading">
                    <svg class="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                </template>
                <span x-text="isLoading ? 'Signing in...' : 'Sign In'"></span>
            </button>
            
            <p class="text-center text-sm text-gray-400 mt-6">
                Don't have an account? <a href="/register" class="text-blue-400 hover:text-blue-300 hover:underline">Register here</a>
            </p>
        </form>
    </div>

    <script>
        document.addEventListener('alpine:init', () => {
            Alpine.data('loginForm', () => ({
                username: '',
                password: '',
                isLoading: false,
                init() {
                    if(localStorage.getItem('access_token')) {
                        window.location.href = '/';
                    }
                },
                async submit() {
                    this.isLoading = true;
                    try {
                        await window.api.login(this.username, this.password);
                        Swal.fire({
                            icon: 'success',
                            title: 'Login Success',
                            text: 'Welcome back!',
                            timer: 1500,
                            showConfirmButton: false
                        }).then(() => {
                            window.location.href = '/';
                        });
                    } catch (e) {
                        Swal.fire({
                            icon: 'error',
                            title: 'Login Failed',
                            text: e.message || 'Check your credentials.',
                            background: '#1e293b',
                            color: '#fff'
                        });
                    } finally {
                        this.isLoading = false;
                    }
                }
            }));
        });
    </script>
</body>
</html>
