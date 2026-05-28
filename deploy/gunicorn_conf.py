import multiprocessing
import os

# Alamat Binding
bind = "127.0.0.1:8000"

# Uvicorn Worker Class (wajib untuk FastAPI)
worker_class = "uvicorn.workers.UvicornWorker"

# Jumlah Worker (Rekomendasi: (2 x $num_cores) + 1)
workers = multiprocessing.cpu_count() * 2 + 1

# Restart worker jika memakan memori/waktu terlalu lama (mencegah memory leak)
max_requests = 1000
max_requests_jitter = 50
timeout = 120

# Logging
loglevel = "info"
accesslog = "/var/log/gunicorn/cybersecurity_access.log"
errorlog = "/var/log/gunicorn/cybersecurity_error.log"

# Eksekusi sebagai user (opsional jika root tidak diinginkan, pastikan user ada)
# user = "ubuntu"
# group = "ubuntu"
