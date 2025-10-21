from django.urls import path, include

# Views içindeki fonksiyonları doğrudan import et (Hata çözüm metodu)
from .views import (
    SayimEmirleriListView, SayimEmriCreateView, PersonelLoginView, 
    set_personel_session, DepoSecimView, SayimGirisView, 
    RaporlamaView, PerformansAnaliziView, CanliFarkOzetiView, KonumAnaliziView, 
    stoklari_onayla_ve_kapat, yonetim_araclari, reset_sayim_data, 
    reload_stok_data_from_excel, ajax_akilli_stok_ara, ajax_sayim_kaydet, 
    gemini_ocr_analiz, export_excel, export_mutabakat_excel,
    

)

urlpatterns = [
    # ----------------------------------------
    # 1. ANA AKIŞ VE EMİR YÖNETİMİ
    # ----------------------------------------
    path('', SayimEmirleriListView.as_view(), name='sayim_emirleri'),
    path('yeni/', SayimEmriCreateView.as_view(), name='yeni_sayim_emri'),

    # 2. PERSONEL GİRİŞİ VE SAYIM
    # Çoklu atama kontrolü artık set_personel_session içinde yapılıyor
    path('login-personel/<int:sayim_emri_id>/<str:depo_kodu>/', PersonelLoginView.as_view(), name='personel_login'),
    path('set-personel/', set_personel_session, name='set_personel_session'),
    path('depo-sec/<int:sayim_emri_id>/', DepoSecimView.as_view(), name='depo_secim'),
    path('giris/<int:pk>/<str:depo_kodu>/', SayimGirisView.as_view(), name='sayim_giris'),

    # 3. RAPORLAMA VE ONAY
    path('rapor/<int:pk>/', RaporlamaView.as_view(), name='raporlama_onay'),
    path('rapor/<int:pk>/export/', export_excel, name='export_excel_rapor'),
    path('onayla/<int:pk>/', stoklari_onayla_ve_kapat, name='stoklari_onayla'),

    # 4. ANALİZ EKRANLARI
    path('analiz/personel/<int:pk>/', PerformansAnaliziView.as_view(), name='analiz_performans'),
    path('analiz/fark/<int:pk>/', CanliFarkOzetiView.as_view(), name='analiz_fark_ozeti'),
    path('analiz/konum/<int:pk>/', KonumAnaliziView.as_view(), name='analiz_konum'),
    path('export_mutabakat/<int:pk>/', export_mutabakat_excel, name='export_mutabakat_excel'),

    # 5. YÖNETİM VE AJAX
    path('yonetim/', yonetim_araclari, name='yonetim_araclari'),
    path('yonetim/reset/', reset_sayim_data, name='reset_sayim_data'),
    path('yonetim/reload/', reload_stok_data_from_excel, name='reload_stok_data'),
    
   
    # AJAX ENDPOINT'LERİ
    path('ajax/stok-ara-akilli/', ajax_akilli_stok_ara, name='ajax_akilli_stok_ara'),
    path('ajax/kaydet/<int:sayim_emri_id>/', ajax_sayim_kaydet, name='ajax_sayim_kaydet'),
    path('ajax/gemini-ocr-analiz/', gemini_ocr_analiz, name='gemini_ocr_analiz'),
]