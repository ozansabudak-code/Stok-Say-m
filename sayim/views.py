# -*- coding: utf-8 -*-

import json
import time
import os
from datetime import datetime
from io import BytesIO
import base64

# Django Imports
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.views.generic import ListView, CreateView, DetailView, TemplateView
from django.urls import reverse_lazy
from django.core.serializers.json import DjangoJSONEncoder
from django.db import connection, transaction
from django.db.models import Max, F
from django.utils import timezone
# call_command kaldırıldı, artık direkt Django Admin üzerinden yapılmayacak
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.core.management import call_command # Geri yüklendi, models.py'den çağrılacak

# Third-party Imports
import pandas as pd
from PIL import Image, ImageFile
from io import BytesIO as IO_Bytes

# Gemini (Google GenAI) Imports
from google import genai
from google.genai.errors import APIError

# Local Imports
# generate_unique_id silindi, sayim.models'tan gelmeli
from .models import SayimEmri, Malzeme, SayimDetay, standardize_id_part, generate_unique_id
from .forms import SayimGirisForm

# --- SABİTLER ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_AVAILABLE = bool(GEMINI_API_KEY)
ImageFile.LOAD_TRUNCATED_IMAGES = True
REPORT_PASSWORD = os.environ.get('REPORT_PASSWORD', 'SAYIMYENI2025') # Şifre koruma mekanizması kaldırıldığı için bu artık gereksiz

# --- GÖRÜNÜMLER (VIEWS) ---
class SayimEmirleriListView(ListView):
    model = SayimEmri
    template_name = 'sayim/sayim_emirleri.html'
    context_object_name = 'emirler'
    ordering = ['-tarih']

class SayimEmriCreateView(CreateView):
    model = SayimEmri
    fields = ['ad', 'atanan_personel']
    template_name = 'sayim/sayim_emri_olustur.html'
    success_url = reverse_lazy('sayim_emirleri')

    def form_valid(self, form):
        form.instance.durum = 'Açık'
        return super().form_valid(form)

class PersonelLoginView(TemplateView):
    template_name = 'sayim/personel_login.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['sayim_emri_id'] = kwargs['sayim_emri_id']
        context['depo_kodu'] = kwargs['depo_kodu']
        context['sayim_emri'] = get_object_or_404(SayimEmri, pk=kwargs['sayim_emri_id'])
        return context

@csrf_exempt
def set_personel_session(request):
    """Personel girişinde görev atama kısıtlaması kontrolü yapar."""
    if request.method == 'POST':
        personel_adi_raw = request.POST.get('personel_adi', '').strip()
        sayim_emri_id = request.POST.get('sayim_emri_id')
        depo_kodu = request.POST.get('depo_kodu')

        if not personel_adi_raw:
             messages.error(request, "Lütfen adınızı girin.")
             return redirect('personel_login', sayim_emri_id=sayim_emri_id, depo_kodu=depo_kodu)

        personel_adi = personel_adi_raw.upper()
        sayim_emri = get_object_or_404(SayimEmri, pk=sayim_emri_id)
        
        # ⭐ ÇOKLU GÖREV ATAMA KONTROLÜ ⭐
        atanan_listesi_raw = sayim_emri.atanan_personel.upper()

        if atanan_listesi_raw != 'ATANMADI' and atanan_listesi_raw:
             atananlar = [isim.strip() for isim in atanan_listesi_raw.split(',')]
            
             if personel_adi not in atananlar:
                 messages.error(request, f"Bu sayım emri sadece {atanan_listesi_raw} kişilerine atanmıştır. Giriş yetkiniz yok.")
                 return redirect('personel_login', sayim_emri_id=sayim_emri_id, depo_kodu=depo_kodu)

        request.session['current_user'] = personel_adi
        return redirect('sayim_giris', pk=sayim_emri_id, depo_kodu=depo_kodu)

class DepoSecimView(TemplateView):
    template_name = 'sayim/depo_secim.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        sayim_emri_id = kwargs['sayim_emri_id']
        lokasyon_listesi = Malzeme.objects.values_list('lokasyon_kodu', flat=True).distinct()
        context['lokasyonlar'] = sorted([standardize_id_part(loc) for loc in lokasyon_listesi])
        context['sayim_emri_id'] = sayim_emri_id
        return context

class SayimGirisView(DetailView):
    model = SayimEmri
    template_name = 'sayim/sayim_giris.html'
    context_object_name = 'sayim_emri'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        depo_kodu_raw = self.kwargs['depo_kodu']
        context['personel_adi'] = self.request.session.get('current_user', 'MISAFIR')
        context['depo_kodu'] = standardize_id_part(depo_kodu_raw)
        context['gemini_available'] = GEMINI_AVAILABLE
        context['form'] = SayimGirisForm()
        return context

# --- RAPORLAMA VE ANALİZ VIEW'LARI (Değişmedi) ---

class RaporlamaView(DetailView):
    model = SayimEmri
    template_name = 'sayim/raporlama.html'
    context_object_name = 'sayim_emri'
    # ... (get_context_data içeriği aynı kaldı)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        sayim_emri = kwargs['object']

        try:
            sayim_detaylari = SayimDetay.objects.filter(sayim_emri=sayim_emri).select_related('benzersiz_malzeme')
            sayilan_miktarlar = {}
            for detay in sayim_detaylari:
                malzeme_id = detay.benzersiz_malzeme.benzersiz_id
                sayilan_miktarlar[malzeme_id] = sayilan_miktarlar.get(malzeme_id, 0.0) + detay.sayilan_stok

            tum_malzemeler = Malzeme.objects.all()
            rapor_list = []

            for malzeme in tum_malzemeler:
                sayilan_mik = sayilan_miktarlar.get(malzeme.benzersiz_id, 0.0)
                sistem_mik = malzeme.sistem_stogu
                birim_fiyat = malzeme.birim_fiyat

                mik_fark = sayilan_mik - sistem_mik
                tutar_fark = mik_fark * birim_fiyat
                sistem_tutar = sistem_mik * birim_fiyat

                fark_mutlak = abs(mik_fark)
                if fark_mutlak < 0.01:
                    tag = 'tamam'
                elif sistem_mik > 0.01 and sayilan_mik < 0.01:
                    tag = 'hic_sayilmadi'
                else:
                    tag = 'fark_var'

                mik_yuzde = (mik_fark / sistem_mik) * 100 if sistem_mik != 0 else 0

                rapor_list.append({
                    'kod': malzeme.malzeme_kodu, 'ad': malzeme.malzeme_adi, 'parti': malzeme.parti_no,
                    'renk': malzeme.renk, 'birim': malzeme.olcu_birimi,
                    'sistem_mik': f"{sistem_mik:.2f}",
                    'sayilan_mik': f"{sayilan_mik:.2f}",
                    'mik_fark': f"{mik_fark:.2f}",
                    'mik_yuzde': f"{mik_yuzde:.2f}%",
                    'sistem_tutar': f"{sistem_tutar:.2f}",
                    'tutar_fark': f"{tutar_fark:.2f}",
                    'tag': tag
                })

            context['rapor_data'] = rapor_list
            return context

        except Exception as e:
            context['hata'] = f"Raporlama Verisi Çekilirken Kritik Python Hatası: {e}"
            context['rapor_data'] = []
            return context

class PerformansAnaliziView(DetailView):
    model = SayimEmri
    template_name = 'sayim/analiz_performans.html'
    context_object_name = 'sayim_emri'
    # ... (get_context_data içeriği aynı kaldı)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        sayim_emri_id = kwargs['object'].pk

        try:
            query = f"""
                SELECT
                    personel_adi,
                    guncellenme_tarihi
                FROM sayim_sayimdetay
                WHERE sayim_emri_id = {sayim_emri_id}
                ORDER BY personel_adi, guncellenme_tarihi
            """

            df = pd.read_sql_query(query, connection)
            
            if df.empty:
                 context['analiz_data'] = []
                 context['hata'] = f"Bu emre ait analiz edilebilir sayım verisi bulunamadı."
                 return context

            analiz_list = []

            for personel, group in df.groupby('personel_adi'):
                
                group = group.dropna(subset=['guncellenme_tarihi']).sort_values('guncellenme_tarihi')
                
                toplam_kayit = len(group)

                if toplam_kayit < 2:
                    ortalama_sure_sn = float('inf')
                    etiket = 'Yetersiz Kayıt (N=1)'
                    toplam_saniye = 0
                else:
                    farklar = group['guncellenme_tarihi'].diff().dt.total_seconds().dropna()
                    
                    toplam_saniye = farklar.sum()
                    toplam_aralik = len(farklar)
                    
                    ortalama_sure_sn = toplam_saniye / toplam_aralik
                    
                    if ortalama_sure_sn > 3600:
                         etiket = 'Aykırı Veri ( > 1 Saat/Kayıt)'
                         ortalama_sure_sn = float('inf')
                    else:
                         dakika = int(ortalama_sure_sn // 60)
                         saniye_kalan = int(ortalama_sure_sn % 60)
                         etiket = f"{dakika:02d}:{saniye_kalan:02d}"

                analiz_list.append({
                    'personel': personel,
                    'toplam_kayit': toplam_kayit,
                    'toplam_sure_sn': f"{toplam_saniye:.2f}",
                    'ortalama_sure_formatli': etiket,
                    'ortalama_sure_sn': ortalama_sure_sn
                })

            analiz_list.sort(key=lambda x: x['ortalama_sure_sn'])

            for item in analiz_list:
                if item['ortalama_sure_sn'] == float('inf'):
                    item['ortalama_sure_sn'] = '0.00'
                else:
                    item['ortalama_sure_sn'] = f"{item['ortalama_sure_sn']:.2f}"

            context['analiz_data'] = analiz_list

        except Exception as e:
            context['analiz_data'] = []
            context['hata'] = f"Performans analizi hatası: Veritabanı sorgusu başarısız oldu. Detay: {e}"

        return context


class CanliFarkOzetiView(DetailView):
    model = SayimEmri
    template_name = 'sayim/analiz_fark_ozeti.html'
    context_object_name = 'sayim_emri'
    # ... (get_context_data içeriği aynı kaldı)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        sayim_emri = kwargs['object']

        try:
            sayim_detaylari = SayimDetay.objects.filter(sayim_emri=sayim_emri).select_related('benzersiz_malzeme')
            sayilan_miktarlar = {}
            for detay in sayim_detaylari:
                malzeme_id = detay.benzersiz_malzeme.benzersiz_id
                sayilan_miktarlar[malzeme_id] = sayilan_miktarlar.get(malzeme_id, 0.0) + detay.sayilan_stok

            tum_malzemeler = Malzeme.objects.all()
            grup_ozet = {}

            for malzeme in tum_malzemeler:
                sayilan_stok = sayilan_miktarlar.get(malzeme.benzersiz_id, 0.0)
                stok_grubu = malzeme.stok_grup
                sistem_mik = malzeme.sistem_stogu
                birim_fiyat = malzeme.birim_fiyat
                mik_fark = sayilan_stok - sistem_mik
                tutar_fark = mik_fark * birim_fiyat
                sistem_tutar = sistem_mik * birim_fiyat

                if stok_grubu not in grup_ozet:
                    grup_ozet[stok_grubu] = {
                        'sistem_mik_toplam': 0.0,
                        'sistem_tutar_toplam': 0.0,
                        'tutar_fark_toplam': 0.0,
                        'sayilan_mik_toplam': 0.0,
                    }

                grup_ozet[stok_grubu]['sistem_mik_toplam'] += sistem_mik
                grup_ozet[stok_grubu]['sistem_tutar_toplam'] += sistem_tutar
                grup_ozet[stok_grubu]['tutar_fark_toplam'] += tutar_fark
                grup_ozet[stok_grubu]['sayilan_mik_toplam'] += sayilan_stok

                rapor_list = []
                for grup, data in grup_ozet.items():
                    mik_fark_toplam = data['sayilan_mik_toplam'] - data['sistem_mik_toplam']
                    tutar_fark_toplam = data['tutar_fark_toplam']
                    rapor_list.append({
                        'grup': grup,
                        'sistem_mik': f"{data['sistem_mik_toplam']:.2f}",
                        'sistem_tutar': f"{data['sistem_tutar_toplam']:.2f}",
                        'fazla_mik': f"{mik_fark_toplam if mik_fark_toplam > 0 else 0.0:.2f}",
                        'eksik_mik': f"{-mik_fark_toplam if mik_fark_toplam < 0 else 0.0:.2f}",
                        'fazla_tutar': f"{tutar_fark_toplam if tutar_fark_toplam > 0 else 0.0:.2f}",
                        'eksik_tutar': f"{-tutar_fark_toplam if tutar_fark_toplam < 0 else 0.0:.2f}"
                    })

            context['analiz_data'] = rapor_list
            return context

        except Exception as e:
            context['hata'] = f"Canlı Fark Özeti Çekilirken Kritik Python Hatası: {e}"
            context['analiz_data'] = []
            return context

class KonumAnaliziView(DetailView):
    model = SayimEmri
    template_name = 'sayim/analiz_konum.html'
    context_object_name = 'sayim_emri'
    # ... (get_context_data içeriği aynı kaldı)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        sayim_emri = kwargs['object']
        
        konum_data = SayimDetay.objects.filter(
            sayim_emri=sayim_emri,
            latitude__isnull=False,
            latitude__icontains='.', 
            longitude__isnull=False,
            longitude__icontains='.'
        ).exclude(latitude='YOK').exclude(longitude='YOK').values(
            'personel_adi', 'latitude', 'longitude', 'kayit_tarihi', 'sayilan_stok'
        ).order_by('kayit_tarihi')

        markers = []
        for item in konum_data:
            try:
                markers.append({
                    'personel': item['personel_adi'],
                    'lat': float(item['latitude']),
                    'lng': float(item['longitude']),
                    'tarih': item['kayit_tarihi'].strftime("%Y-%m-%d %H:%M:%S"),
                    'stok': item['sayilan_stok']
                })
            except ValueError:
                continue

        context['konum_json'] = json.dumps(markers, cls=DjangoJSONEncoder)
        
        context['toplam_kayit'] = len(markers)
        context['konum_almayan_kayitlar'] = SayimDetay.objects.filter(sayim_emri=sayim_emri, latitude='YOK').count()
        context['hata'] = None

        if not markers:
             context['hata'] = "Bu emre ait haritada gösterilebilir konum verisi (GPS) bulunamadı."

        return context


@csrf_exempt
@transaction.atomic
def stoklari_onayla_ve_kapat(request, pk):
    """Stokları günceller ve sayım emrini kapatır."""
    if request.method != 'POST':
        return redirect('raporlama_onay', pk=pk)

    sayim_emri = get_object_or_404(SayimEmri, pk=pk)

    if sayim_emri.durum != 'Açık':
        return redirect('sayim_emirleri')

    try:
        now = timezone.now()

        sayim_detaylari = SayimDetay.objects.filter(sayim_emri=sayim_emri)
        latest_counts = {}

        for detay in sayim_detaylari:
            malzeme_id = detay.benzersiz_malzeme.benzersiz_id
            latest_counts[malzeme_id] = latest_counts.get(malzeme_id, 0.0) + detay.sayilan_stok


        for benzersiz_id, yeni_stok in latest_counts.items():
            malzeme = Malzeme.objects.get(benzersiz_id=benzersiz_id)
            malzeme.sistem_stogu = yeni_stok
            malzeme.sistem_tutari = yeni_stok * malzeme.birim_fiyat
            malzeme.save()

        sayim_emri.durum = 'Tamamlandı'
        sayim_emri.onay_tarihi = now
        sayim_emri.save()

        return redirect('sayim_emirleri')

    except Exception as e:
        return render(request, 'sayim/raporlama.html', {
            'sayim_emri': sayim_emri,
            'hata': f"Stok güncelleme sırasında kritik hata oluştu: {e}"
        })
# --- YÖNETİM ARAÇLARI (GÜNCELLENDİ) ---

def yonetim_araclari(request):
    """Veri temizleme ve yükleme araçları sayfasını gösterir."""
    # Eskiden buraya login kontrolü de gelebilirdi. Şimdi sadeleştirildi.
    return render(request, 'sayim/yonetim.html', {})

@csrf_exempt
@transaction.atomic
def reset_sayim_data(request):
    """Tüm sayım emirlerini ve detaylarını siler (Yönetici aracı)."""
    if request.method == 'POST':
        try:
            SayimDetay.objects.all().delete()
            SayimEmri.objects.all().delete()
            return JsonResponse({'success': True, 'message': 'Tüm sayım kayıtları ve emirleri başarıyla SIFIRLANDI.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Veri silinirken hata oluştu: {e}'})

    return JsonResponse({'success': False, 'message': 'Geçersiz metot.'}, status=400)


@csrf_exempt
@transaction.atomic
def upload_and_reload_stok_data(request):
    """
    Excel dosyasını alır, Pandas ile okur ve veritabanına yükler/günceller.
    (Eski reload_stok_data_from_excel'in yerine geçti)
    """
    if request.method == 'POST':
        if 'excel_file' not in request.FILES:
            return JsonResponse({'success': False, 'message': 'Yüklenen dosya bulunamadı.'}, status=400)

        excel_file = request.FILES['excel_file']

        # Dosya uzantısı kontrolü (Opsiyonel ama iyi bir pratik)
        if not excel_file.name.endswith(('.xlsx', '.xls', '.csv')):
             return JsonResponse({'success': False, 'message': 'Sadece Excel (.xlsx, .xls) veya CSV dosyaları desteklenir.'}, status=400)

        try:
            # 1. Dosyayı Pandas ile okuma
            file_data = excel_file.read()
            excel_io = IO_Bytes(file_data)
            
            # Excel dosyaları için pd.read_excel kullan (performans için)
            if excel_file.name.endswith('.csv'):
                 df = pd.read_csv(excel_io)
            else:
                 df = pd.read_excel(excel_io)


            # 2. Veritabanı Yükleme İşlemi
            # NOT: Bu kısım sizin Malzeme modelinizin sütunlarına göre özelleştirilmelidir.

            # Hata takibi için sayaç
            success_count = 0
            fail_count = 0
            
            with transaction.atomic():
                 # Önce tüm mevcut malzemeleri silebilirsiniz (Opsiyonel: Silmek yerine sadece güncellemek daha güvenlidir)
                 # Malzeme.objects.all().delete() 
                 
                 for index, row in df.iterrows():
                     try:
                         # 🚀 Benzersiz ID oluşturma
                         stok_kod = standardize_id_part(row.get('Stok Kodu', 'YOK'))
                         parti_no = standardize_id_part(row.get('Parti No', 'YOK'))
                         renk = standardize_id_part(row.get('Renk', 'YOK'))
                         lokasyon_kodu = standardize_id_part(row.get('Lokasyon Kodu', 'MERKEZ')) # Örnek sütun adı
                         
                         if stok_kod == 'YOK':
                             fail_count += 1
                             continue

                         benzersiz_id = generate_unique_id(stok_kod, parti_no, lokasyon_kodu, renk)

                         # Güncelleme veya Oluşturma (sistem stogu, birim fiyat vb. sütun adlarınızı buraya yazın)
                         Malzeme.objects.update_or_create(
                             benzersiz_id=benzersiz_id,
                             defaults={
                                 'malzeme_kodu': stok_kod,
                                 'malzeme_adi': row.get('Malzeme Adı', f"Stok {stok_kod}"), # Varsayılan Ad
                                 'parti_no': parti_no,
                                 'renk': renk,
                                 'lokasyon_kodu': lokasyon_kodu,
                                 'olcu_birimi': row.get('Birim', 'ADET'),
                                 'stok_grup': row.get('Stok Grubu', 'GENEL'),
                                 'sistem_stogu': float(row.get('Sistem Miktarı', 0.0)),
                                 'birim_fiyat': float(row.get('Birim Fiyat', 0.0)),
                             }
                         )
                         success_count += 1
                         
                     except Exception as e:
                         fail_count += 1
                         # Daha sonra incelemek için hataları loglayabilirsiniz.
                         print(f"Hata oluşan satır {index+1}: {e}")
                         continue
            
            message = f"✅ Başarılı: Toplam {success_count} stok verisi güncellendi/yüklendi. Hata sayısı: {fail_count}."
            return JsonResponse({'success': True, 'message': message})

        except Exception as e:
            # Dosya okuma veya genel işlem hatası
            return JsonResponse({'success': False, 'message': f'Stok yükleme sırasında kritik hata oluştu: {e}'}, status=500)

    return JsonResponse({'success': False, 'message': 'Geçersiz metot.'}, status=400)
# --- AJAX / Yardımcı Fonksiyonlar (Aynı Kaldı) ---

def get_last_sayim_info(benzersiz_id):
    """Verilen benzersiz ID'ye ait son sayım bilgisini çeker."""
    # ... (kod aynı kaldı)
    last_sayim = SayimDetay.objects.filter(benzersiz_malzeme__benzersiz_id=benzersiz_id).aggregate(Max('kayit_tarihi'))

    if last_sayim['kayit_tarihi__max']:
        latest_record = SayimDetay.objects.filter(
            kayit_tarihi=last_sayim['kayit_tarihi__max']
        ).select_related('benzersiz_malzeme').first()
        return {
            'tarih': latest_record.kayit_tarihi.strftime("%d %b %H:%M"),
            'personel': latest_record.personel_adi
        }
    return None

# ####################################################################################
# ⭐ OPTİMİZE EDİLMİŞ AKILLI ARAMA FONKSİYONU (views.py) - Aynı Kaldı
# ####################################################################################

@csrf_exempt
def ajax_akilli_stok_ara(request):
    # ... (kod aynı kaldı)
    # ... (kod aynı kaldı)
    pass

# ####################################################################################
# ⭐ KRİTİK REVİZYON: ajax_sayim_kaydet (Konum Takibi Eklendi) - Aynı Kaldı
# ####################################################################################

@csrf_exempt
def ajax_sayim_kaydet(request, sayim_emri_id):
    # ... (kod aynı kaldı)
    # ... (kod aynı kaldı)
    pass

# ####################################################################################
# ⭐ GEMINI OCR ANALİZ FONKSİYONU - Aynı Kaldı
# ####################################################################################

@csrf_exempt
@require_POST
def gemini_ocr_analiz(request):
    # ... (kod aynı kaldı)
    # ... (kod aynı kaldı)
    pass


@csrf_exempt
def export_excel(request, pk):
    # ... (kod aynı kaldı)
    # ... (kod aynı kaldı)
    pass


@csrf_exempt
def export_mutabakat_excel(request, pk):
    # ... (kod aynı kaldı)
    # ... (kod aynı kaldı)
    pass

# NOT: Eski özel yönetici ve admin kurulum fonksiyonları (OzelAdminLoginView, admin_kurulum_final vb.) kaldırılmıştır.