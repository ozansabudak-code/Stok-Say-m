# start_server.py içeriği
import os
import subprocess
import sys

# 1. Proje ana dizinini belirle (Bu betiğin çalıştığı yer)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Venv içindeki python.exe yolunu belirle (Sizin sisteminizdeki yol)
# Bu yolu kontrol edin ve gerekirse düzenleyin!
PYTHON_EXECUTABLE = os.path.join(BASE_DIR, 'venv', 'Scripts', 'python.exe')

# 3. Waitress'i başlatmak için komutu oluştur
# waitress-serve, venv içindeki python.exe tarafından çalıştırılacak
COMMAND = [
    PYTHON_EXECUTABLE,
    '-m', 
    'waitress_serve', # Waitress modül adı
    '--listen=0.0.0.0:8000', 
    'stock_project.wsgi:application'
]

# 4. Komutu gizli ve arka planda çalıştır
# Windows için SW_HIDE (0) komut penceresini gizler.
# subprocess.CREATE_NEW_CONSOLE da gerekebilir, ancak STARTUPINFO genellikle yeterlidir.

try:
    # Windows'a özel ayarlamalar
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.SW_HIDE # Pencereyi gizle
    
    # Komutu çalıştır
    subprocess.Popen(
        COMMAND, 
        cwd=BASE_DIR, # Çalışma dizinini proje kökü olarak ayarla
        startupinfo=startupinfo,
        creationflags=subprocess.CREATE_NO_WINDOW # Yeni pencere oluşturma
    )
    # Programı hemen sonlandır (bu betik sadece başlatıcı görevi görüyor)
    sys.exit(0) 

except Exception as e:
    # Hata durumunda (Örn: python.exe yolu yanlışsa) hata mesajı yazdırılabilir.
    with open(os.path.join(BASE_DIR, 'startup_error.log'), 'w') as f:
        f.write(f"Hata: {e}\nKomut: {COMMAND}")