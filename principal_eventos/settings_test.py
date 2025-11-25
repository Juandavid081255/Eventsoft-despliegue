from .settings import *

# Base de datos en MEMORIA (ultra rápido)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Password hasher rápido
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Sin logs
LOGGING_CONFIG = None
import logging
logging.disable(logging.CRITICAL)