"""
Django settings for stock_project project.
"""

from pathlib import Path
import os
import dj_database_url
# Whitenoise, production ortamında statik dosyaları sunmak için önerilir.

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# --- 1. GÜVENLİK VE ANAHTAR YÖNETİMİ (ZORUNLU) ---
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    # Bu kontrol, anahtarın ayarlanmadığı durumlarda uygulamanın başlamasını engeller.
    pass 

# DEBUG'ı ortam değişkeninden oku. DEBUG_VALUE='True' ise DEBUG=True olur.
DEBUG = os.environ.get('DEBUG_VALUE') == 'True'

# İzin verilen sunucular, Render domainleri ve özel domain'ler için
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '127.0.0.1,localhost').split(',') 
ALLOWED_HOSTS.append('.render.com') 

# === 🚨 400 Bad Request Hatası Çözümü: Render Host Adını Ekleme ===
# Render'dan gelen tam host adını alıp ALLOWED_HOSTS listesine ekler.
# Bu, https://stok-35vx.onrender.com gibi adreslerin tanınmasını sağlar.
RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME) 

# --- 2. UYGULAMA TANIMLARI ---

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'sayim'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    # === 🚨 DÜZELTME: Whitenoise Aktif Edildi (Statik Dosyalar (CSS/JS) İçin) ===
    'whitenoise.middleware.WhiteNoiseMiddleware', 
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# --- RENDER GÜVENLİK AYARLARI ---
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
CSRF_TRUSTED_ORIGINS = ['https://*.render.com'] 

ROOT_URLCONF = 'stock_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'stock_project.wsgi.application'


# --- 3. VERİTABANI AYARLARI (RENDER İÇİN POSTGRESQL) ---
try:
    DATABASES = {
        'default': dj_database_url.config(
            default=os.environ.get('DATABASE_URL'),
            conn_max_age=600 
        )
    }
except Exception:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }


# ... (Password validation, Internationalization ayarları aynı kalır) ...


# --- 4. STATİK DOSYALAR (PRODUCTION İÇİN ZORUNLU) ---

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
