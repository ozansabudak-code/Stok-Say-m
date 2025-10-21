from django.db import models
from django.utils import timezone 

# --- MERKEZİ ID TEMİZLEME VE OLUŞTURMA FONKSİYONLARI ---

def standardize_id_part(value):
    """
    ID'yi oluşturan bir parçayı temizler ve standartlaştırır (Büyük harf, YOK kontrolü).
    """
    cleaned = str(value).strip().upper()
    if not cleaned or cleaned in ('NAN', 'NONE', 'NULL', 'NA'):
        return 'YOK'
    return cleaned

def generate_unique_id(stok_kod, parti_no, lokasyon_kod, renk):
    """
    Standartlaştırılmış parçalardan ana benzersiz ID'yi oluşturur.
    """
    stok_kod_s = standardize_id_part(stok_kod)
    parti_no_s = standardize_id_part(parti_no)
    lokasyon_kod_s = standardize_id_part(lokasyon_kod)
    renk_s = standardize_id_part(renk)
    
    return f"{stok_kod_s}_{parti_no_s}_{lokasyon_kod_s}_{renk_s}"

# --------------------------------------------------------

class Malzeme(models.Model):
    # Ana Benzersiz Tanımlayıcı
    benzersiz_id = models.CharField(max_length=255, unique=True, db_index=True, editable=False)
    
    # Yeni Eklenen Alan: Seri No (Akıllı arama için öncelikli anahtar)
    seri_no = models.CharField(max_length=100, null=True, blank=True, default='YOK', db_index=True)
    
    # Stok Tanımlama Alanları
    malzeme_kodu = models.CharField(max_length=100)
    parti_no = models.CharField(max_length=100, null=True, blank=True, default='YOK')
    lokasyon_kodu = models.CharField(max_length=100, default='YOK')
    renk = models.CharField(max_length=50, null=True, blank=True, default='YOK')
    
    # Açıklayıcı Alanlar
    depo_adi = models.CharField(max_length=100, null=True, blank=True)
    stok_grup = models.CharField(max_length=100, null=True, blank=True)
    depo_sinif = models.CharField(max_length=100, null=True, blank=True)
    malzeme_adi = models.CharField(max_length=255)
    barkod = models.CharField(max_length=100, null=True, blank=True)
    olcu_birimi = models.CharField(max_length=20)
    
    # Stok/Finansal Alanlar
    sistem_stogu = models.FloatField(default=0.0)
    sistem_tutari = models.FloatField(default=0.0)
    birim_fiyat = models.FloatField(default=0.0)

    class Meta:
        verbose_name = "Malzeme"
        verbose_name_plural = "Malzemeler"
        
    def __str__(self):
        return f"{self.malzeme_kodu} ({self.benzersiz_id})"

    def save(self, *args, **kwargs):
        # Kayıt edilmeden hemen önce benzersiz_id'yi hesapla
        self.benzersiz_id = generate_unique_id(
            self.malzeme_kodu, 
            self.parti_no, 
            self.lokasyon_kodu, 
            self.renk
        )
        super().save(*args, **kwargs)

# --- SAYIM YÖNETİM MODELLERİ ---

class SayimEmri(models.Model):
    DURUM_SECENEKLERI = [
        ('Açık', 'Açık'),
        ('Tamamlandı', 'Tamamlandı'),
    ]

    ad = models.CharField(max_length=255)
    tarih = models.DateTimeField(default=timezone.now)
    durum = models.CharField(max_length=20, choices=DURUM_SECENEKLERI, default='Açık')
    onay_tarihi = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Sayım Emri"
        verbose_name_plural = "Sayım Emirleri"
        
    def __str__(self):
        return f"Emir ID:{self.pk} - {self.ad} ({self.durum})"


class SayimDetay(models.Model):
    sayim_emri = models.ForeignKey(SayimEmri, on_delete=models.CASCADE)

    # Personelin bir önceki kaydı ile arasındaki zamanı hesaplamak için kullanılır
    guncellenme_tarihi = models.DateTimeField(auto_now=True) 
    
    # Malzeme modeline Foreign Key bağlantısı (Benzersiz ID'yi temsil eder)
    benzersiz_malzeme = models.ForeignKey(Malzeme, on_delete=models.CASCADE) 
    
    sayilan_stok = models.FloatField()
    kayit_tarihi = models.DateTimeField(default=timezone.now)
    personel_adi = models.CharField(max_length=100)
    saniye_stamp = models.FloatField(default=0.0)

    # ⭐ YENİ EKLENEN KONUM ALANLARI
    latitude = models.CharField(max_length=50, default='YOK', blank=True, null=True)
    longitude = models.CharField(max_length=50, default='YOK', blank=True, null=True)
    loc_hata = models.CharField(max_length=255, default='', blank=True, null=True)

    class Meta:
        verbose_name = "Sayım Detay"
        verbose_name_plural = "Sayım Detayları"
        # Bir sayım emrinde aynı malzemeden (benzersiz_malzeme) birden fazla sayım kaydı olmaması için
        unique_together = (('sayim_emri', 'benzersiz_malzeme'),)

    def __str__(self):
        return f"{self.benzersiz_malzeme.malzeme_kodu} - {self.sayilan_stok} sayıldı"