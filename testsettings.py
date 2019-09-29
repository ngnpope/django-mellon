import os
import django
from django.conf import global_settings

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.' + os.environ.get('DB_ENGINE', 'sqlite3'),
        'NAME': 'mellon.sqlite3',
        'TEST': {
            'NAME': 'mellon-test-' + os.environ.get('DB_ENGINE', 'sqlite3'),
        },
    }
}
DEBUG = True
SECRET_KEY = 'xx'
STATIC_URL = '/static/'
INSTALLED_APPS = ('mellon', 'django.contrib.auth',
                  'django.contrib.contenttypes', 'django.contrib.sessions')
if hasattr(global_settings, 'MIDDLEWARE_CLASSES'):
    MIDDLEWARE_CLASSES = global_settings.MIDDLEWARE_CLASSES
    MIDDLEWARE_CLASSES += (
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'mellon.middleware.PassiveAuthenticationMiddleware',
    )
else:
    MIDDLEWARE = global_settings.MIDDLEWARE
    MIDDLEWARE += (
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'mellon.middleware.PassiveAuthenticationMiddleware',
    )

AUTHENTICATION_BACKENDS = (
    'mellon.backends.SAMLBackend',
)
ROOT_URLCONF = 'urls_tests'
TEMPLATE_DIRS = [
    'tests/templates/',
]
if django.VERSION >= (1, 8):
    TEMPLATES = [
        {
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'APP_DIRS': True,
            'DIRS': TEMPLATE_DIRS,
        },
    ]
