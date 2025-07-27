# gunicorn_config.py

# This is the address and port your Gunicorn server will bind to.
# It should only be accessible from your HAProxy server.
bind = "127.0.0.1:5050"

# The number of worker processes for handling requests.
# A good starting point is (2 x number of CPU cores) + 1.
workers = 3

# This is the crucial setting. It tells Gunicorn to trust the
# X-Forwarded-For and X-Forwarded-Proto headers from your reverse proxy.
# '*' allows all IPs, but for better security, you could restrict
# this to your HAProxy server's IP address (e.g., "127.0.0.1").
forwarded_allow_ips = '*'

# Set the user and group to run the Gunicorn process.
# This is a good security practice but is optional.
# user = "www-data"
# group = "www-data"

# Path to log files
accesslog = 'gunicorn_access.log'
errorlog = 'gunicorn_error.log'