"""
Django settings for stock_project project.
"""

from pathlib import Path
import os
# dj_database_url import'ını yorum satırına alıyoruz, çünkü artık kullanmayacağız.
# import dj_database_url 

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# ----------------------------------------------------------------------
# 1. GÜVENLİK VE ANAHTAR YÖNETİMİ
# ----------------------------------------------------------------------

# SECRET_KEY'i sabit bir değer olarak ayarlıyoruz. Üretimde bu değiştirilmelidir.
SECRET_KEY = 'django-insecure-t-m^d)r7_p^6&y#c2(6%y-!*v2b3@41$a%9*&d3^s#u*^w!@1' 

# Yerel geliştirme ortamında her zaman True yapıyoruz.
DEBUG = True 

# Yerel ortamlar için izin verilen hostlar.
ALLOWED_HOSTS = ['127.0.0.1', 'localhost', '::1']

# RENDER ile ilgili tüm ortam değişkeni okuma ve host ekleme satırları SİLİNDİ.


# ----------------------------------------------------------------------
# 2. UYGULAMA TANIMLARI
# ----------------------------------------------------------------------

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Kendi Uygulamanız
    'sayim' 
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    # Yerel ortamda Whitenoise'a gerek yoktur, ancak kalması sorun yaratmaz.
    'whitenoise.middleware.WhiteNoiseMiddleware', 
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

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

# ----------------------------------------------------------------------
# 3. VERİTABANI AYARLARI (SADECE YEREL SQLite)
# ----------------------------------------------------------------------
# Bu kısım, önceki hatayı veren tüm karmaşık mantıktan arındırılmıştır.
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# ----------------------------------------------------------------------
# 4. GÜVENLİK VE ŞİFRE DOĞRULAMALARI
# ----------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# ----------------------------------------------------------------------
# 5. ULUSLARARASI DİL AYARLARI
# ----------------------------------------------------------------------

LANGUAGE_CODE = 'tr-TR'

TIME_ZONE = 'Europe/Istanbul' 

USE_I18N = True

USE_TZ = True


# ----------------------------------------------------------------------
# 6. STATİK DOSYALAR
# ----------------------------------------------------------------------

STATIC_URL = '/static/'

# STATIC_ROOT'un varlığını kontrol etmeden sadece tanımlıyoruz.
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Sayım klasöründeki statik dosyaları gösterir.
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

# Whitenoise yerine varsayılan depolamayı kullanıyoruz.
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'


# ----------------------------------------------------------------------
# 7. DİĞER AYARLAR
# ----------------------------------------------------------------------

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'