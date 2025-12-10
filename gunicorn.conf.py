import multiprocessing

workers = multiprocessing.cpu_count() * 2 + 1
timeout = 120
keepalive = 2
bind = "0.0.0.0:10000"
worker_class = "uvicorn.workers.UvicornWorker"
max_requests = 1000
max_requests_jitter = 50