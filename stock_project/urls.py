from django.contrib import admin
from django.urls import path, include # 'include' ekledik

urlpatterns = [
    # Admin paneli (eski hali)
    path('admin/', admin.site.urls),
    
    # Ana adres (http://127.0.0.1:8000/) sayim/urls.py'ye yönlendirilir.
    path('', include('sayim.urls')), 
]