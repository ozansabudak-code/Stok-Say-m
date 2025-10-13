from django.contrib import admin
from .models import Malzeme, SayimEmri, SayimDetay # Tüm modelleri import edin

# Malzeme modelini daha detaylı ayarlar ile kaydet
@admin.register(Malzeme)
class MalzemeAdmin(admin.ModelAdmin):
    # Yönetici listesinde görünecek alanlar
    list_display = ('malzeme_kodu', 'malzeme_adi', 'parti_no', 'lokasyon_kodu', 'sistem_stogu')
    
    # Arama yapabileceğiniz alanlar
    search_fields = ('malzeme_kodu', 'barkod', 'parti_no', 'benzersiz_id')
    
    # Filtreleme yapabileceğiniz alanlar
    list_filter = ('lokasyon_kodu', 'stok_grup')
    
    # Benzersiz ID'nin otomatik oluştuğunu gösteren salt okunur alanlar
    readonly_fields = ('benzersiz_id',)

# Sayım Emirleri ve Sayım Detaylarını basitçe kaydet
admin.site.register(SayimEmri)
admin.site.register(SayimDetay)