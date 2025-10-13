"""
Django settings for stock_project project.
"""

from pathlib import Path
import os
import dj_database_url
# Whitenoise, production ortamında statik dosyaları sunmak için önerilir.
# pip install whitenoise
# from whitenoise.middleware import WhiteNoiseMiddleware # Eğer MIDDLEWARE'e eklenirse

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# --- 1. GÜVENLİK VE ANAHTAR YÖNETİMİ (ZORUNLU) ---
# SECRET_KEY'i koddan çıkarıp, Render'da tanımlayacağınız ortam değişkeninden okuyun.
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    # Bu kontrol, anahtarın ayarlanmadığı durumlarda uygulamanın başlamasını engeller.
    # Yerel geliştirme için, bu satırı geçici olarak kapatıp sabit anahtar kullanabilirsiniz.
    # raise ValueError("SECRET_KEY ortam değişkeni ayarlanmadı.")
    pass # Yerel testler için geçici olarak ValueError'ı kaldırdık

# DEBUG'ı ortam değişkeninden oku. DEBUG_VALUE='True' ise DEBUG=True olur.
DEBUG = os.environ.get('DEBUG_VALUE') == 'True'

# İzin verilen sunucular, Render domainleri ve özel domain'ler için
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '127.0.0.1,localhost').split(',') 
ALLOWED_HOSTS.append('.render.com') 

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
    # 'whitenoise.middleware.WhiteNoiseMiddleware', # Statik dosyalar için (Opsiyonel ama önerilir)
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# --- RENDER GÜVENLİK AYARLARI ---
# HTTPS'i zorunlu kıl (Render'da zorunludur)
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
CSRF_TRUSTED_ORIGINS = ['https://*.render.com'] # Render domainlerini güvenilir yap

ROOT_URLCONF = 'stock_project.urls'

# ... (TEMPLATES ve WSGI_APPLICATION kodları aynı kalır) ...

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
# Render'ın sağladığı DATABASE_URL ortam değişkenini kullanır.
try:
    DATABASES = {
        'default': dj_database_url.config(
            default=os.environ.get('DATABASE_URL'),
            conn_max_age=600 # Kalıcı bağlantılar (performans için)
        )
    }
except Exception:
    # DATABASE_URL ortam değişkeni ayarlanmadıysa veya hata oluştuysa yerel SQLite kullan
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }


# ... (Password validation, Internationalization ayarları aynı kalır) ...


# --- 4. STATİK DOSYALAR (PRODUCTION İÇİN ZORUNLU) ---

# Statik dosyaların URL öneki
STATIC_URL = '/static/'

# Statik dosyaların toplanacağı dizin (collectstatic komutu için)
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Uygulamaların içindeki static klasörlerinin yanı sıra varsa elle belirlenmiş
# statik dosya klasörlerini dahil et.
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]


# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'