import os

# Web Configuration
WEB_USERNAME = 'admin'
WEB_PASSWORD = 'password'
FLASK_SECRET_KEY = 'change-me'

# Debug switch for proxmoxer/requests verbose logs
# Set environment variable HTTP_DEBUG to 1/true/yes to enable without editing this file
ENABLE_HTTP_DEBUG = (
    os.getenv('HTTP_DEBUG', '0').lower() in ('1', 'true', 'yes', 'on')
)

# Include sensitive values like OTP/password/token in logs (not recommended)
# Enable by env var HTTP_DEBUG_SHOW_SECRETS=1/true/yes/on
ENABLE_HTTP_DEBUG_SHOW_SECRETS = (
    os.getenv('HTTP_DEBUG_SHOW_SECRETS', '0').lower() in ('1', 'true', 'yes', 'on')
)
