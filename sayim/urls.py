from django.urls import path
from . import views

urlpatterns = [
    # ----------------------------------------
    # 1. ANA AKIŞ VE EMİR YÖNETİMİ
    # ----------------------------------------
    # Sayım Emirleri Listesi (ListView)
    path('', views.SayimEmirleriListView.as_view(), name='sayim_emirleri'), 
    # Yeni Sayım Emri (CreateView)
    path('yeni/', views.SayimEmriCreateView.as_view(), name='yeni_sayim_emri'),
    
    # 2. PERSONEL GİRİŞİ VE SAYIM
    # Personel Giriş (TemplateView)
    path('login-personel/<int:sayim_emri_id>/<str:depo_kodu>/', views.PersonelLoginView.as_view(), name='personel_login'),
    # Personel Session Ayarlama (Fonksiyon)
    path('set-personel/', views.set_personel_session, name='set_personel_session'),
    # Depo Seçim (TemplateView)
    path('depo-sec/<int:sayim_emri_id>/', views.DepoSecimView.as_view(), name='depo_secim'), 
    # Sayım Girişi (DetailView)
    path('giris/<int:pk>/<str:depo_kodu>/', views.SayimGirisView.as_view(), name='sayim_giris'),
    
    # 3. RAPORLAMA VE ONAY
    # Raporlama View (DetailView)
    path('rapor/<int:pk>/', views.RaporlamaView.as_view(), name='raporlama_onay'),
    path('rapor/<int:pk>/export/', views.export_excel, name='export_excel_rapor'), 
    # Stok Onayı (Fonksiyon)
    path('onayla/<int:pk>/', views.stoklari_onayla_ve_kapat, name='stoklari_onayla'), 
    
    # 4. ANALİZ EKRANLARI
    # Performans Analizi (DetailView)
    path('analiz/personel/<int:pk>/', views.PerformansAnaliziView.as_view(), name='analiz_performans'), 
    # Canlı Fark Özeti (DetailView)
    path('analiz/fark/<int:pk>/', views.CanliFarkOzetiView.as_view(), name='analiz_fark_ozeti'), 
    path('export_excel/<int:pk>/', views.export_excel, name='export_excel'),
    path('export_mutabakat/<int:pk>/', views.export_mutabakat_excel, name='export_mutabakat_excel'),


    # 5. YÖNETİM VE AJAX
    # Yönetim Araçları (Fonksiyon)
    path('yonetim/', views.yonetim_araclari, name='yonetim_araclari'), 
    path('yonetim/reset/', views.reset_sayim_data, name='reset_sayim_data'), 
    path('yonetim/reload/', views.reload_stok_data_from_excel, name='reload_stok_data'), 
    
    # AJAX ENDPOINT'LERİ
    path('ajax/stok-ara/', views.ajax_stok_ara, name='ajax_stok_ara'),
    path('ajax/kaydet/<int:sayim_emri_id>/', views.ajax_sayim_kaydet, name='ajax_sayim_kaydet'),
    path('ajax/gemini-oku/', views.gemini_parti_oku, name='gemini_parti_oku'),
    
]
