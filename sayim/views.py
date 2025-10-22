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
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.views.generic import ListView, CreateView, DetailView, TemplateView
from django.urls import reverse_lazy
from django.core.serializers.json import DjangoJSONEncoder
from django.db import connection, transaction
from django.db.models import Max, F 
from django.utils import timezone
from django.core.management import call_command
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User 

# Third-party Imports
from PIL import Image
import pandas as pd
from PIL import Image, ImageFile

# Gemini (Google GenAI) Imports
from google import genai
from google.genai.errors import APIError

# Local Imports
from .models import SayimEmri, Malzeme, SayimDetay, standardize_id_part, generate_unique_id
from .forms import SayimGirisForm

# --- SABİTLER ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_AVAILABLE = bool(GEMINI_API_KEY)
ImageFile.LOAD_TRUNCATED_IMAGES = True
REPORT_PASSWORD = os.environ.get('REPORT_PASSWORD', 'SAYIMYENI2025') # Özel Yönetici Şifresi

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

    return redirect('depo_secim', sayim_emri_id=request.GET.get('sayim_emri_id'))


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

# --- RAPORLAMA VE ANALİZ VIEW'LARI ---
# Not: Bu View'lar artık OzelYonetimPanelView içinden çağrılacaktır.

class RaporlamaView(DetailView):
    model = SayimEmri
    template_name = 'sayim/raporlama.html'
    context_object_name = 'sayim_emri'

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

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        sayim_emri_id = kwargs['object'].pk

        try:
            # KRİTİK REVİZYON: Sadece gerekli verileri çekmek için SQL sorgusu basitleştirildi.
            query = f"""
                SELECT
                    personel_adi,
                    guncellenme_tarihi
                FROM sayim_sayimdetay
                WHERE sayim_emri_id = {sayim_emri_id}
                ORDER BY personel_adi, guncellenme_tarihi
            """

            # Pandas ile veriyi çek
            df = pd.read_sql_query(query, connection)
            
            # Eğer analiz edilebilir veri yoksa hemen dön
            if df.empty:
                 context['analiz_data'] = []
                 context['hata'] = f"Bu emre ait analiz edilebilir sayım verisi bulunamadı."
                 return context

            analiz_list = []

            # Performans hesaplaması artık PYTHON/PANDAS içinde yapılıyor
            for personel, group in df.groupby('personel_adi'):
                
                # Sadece geçerli tarih damgası olanları al ve sırala
                group = group.dropna(subset=['guncellenme_tarihi']).sort_values('guncellenme_tarihi')
                
                toplam_kayit = len(group)

                if toplam_kayit < 2:
                    # Tek kayıt varsa hız hesaplanamaz.
                    ortalama_sure_sn = float('inf') 
                    etiket = 'Yetersiz Kayıt (N=1)'
                    toplam_saniye = 0
                else:
                    # Kayıtlar arası farkı saniye cinsinden hesapla
                    farklar = group['guncellenme_tarihi'].diff().dt.total_seconds().dropna()
                    
                    toplam_saniye = farklar.sum()
                    toplam_aralik = len(farklar) # N kayıt için N-1 aralık vardır
                    
                    ortalama_sure_sn = toplam_saniye / toplam_aralik
                    
                    # --- Ortalama Süre Formatlama ---
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
                    'ortalama_sure_sn': ortalama_sure_sn # Sıralama için ham değeri tut
                })

            # Analiz listesini Ortalama süreye göre sırala
            analiz_list.sort(key=lambda x: x['ortalama_sure_sn'])

            # Gösterim için 'inf' olanları düzelt
            for item in analiz_list:
                if item['ortalama_sure_sn'] == float('inf'):
                    item['ortalama_sure_sn'] = '0.00'
                else:
                    item['ortalama_sure_sn'] = f"{item['ortalama_sure_sn']:.2f}"

            context['analiz_data'] = analiz_list

        except Exception as e:
            # Hata mesajını daha kullanıcı dostu yap
            context['analiz_data'] = []
            context['hata'] = f"Performans analizi hatası: Veritabanı sorgusu başarısız oldu. Detay: {e}"

        return context

class CanliFarkOzetiView(DetailView):
    model = SayimEmri
    template_name = 'sayim/analiz_fark_ozeti.html'
    context_object_name = 'sayim_emri'

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

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        sayim_emri = kwargs['object']
        
        # Sadece geçerli koordinatlara sahip kayıtları çek
        konum_data = SayimDetay.objects.filter(
            sayim_emri=sayim_emri,
            latitude__isnull=False,
            latitude__icontains='.', 
            longitude__isnull=False,
            longitude__icontains='.'
        ).exclude(latitude='YOK').exclude(longitude='YOK').values(
            'personel_adi', 'latitude', 'longitude', 'kayit_tarihi', 'sayilan_stok'
        ).order_by('kayit_tarihi')

        # Harita üzerinde kullanmak için veriyi JSON formatına dönüştür
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

        # Harita verisini JSON dizesi olarak template'e gönder
        context['konum_json'] = json.dumps(markers, cls=DjangoJSONEncoder)
        
        # Sadece konum verisi olan personel sayısını göster
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
            # NOTE: Bu kısımda, en son sayılan miktarı alıp üzerine yazmak yerine,
            # Malzeme/Emir bazında toplanan miktarı alıyoruz.
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
# --- YÖNETİM ARAÇLARI (DEĞİŞMEDİ) ---

def yonetim_araclari(request):
    """Veri temizleme ve yükleme araçları sayfasını gösterir."""
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
def reload_stok_data_from_excel(request):
    """Excel yükleme işlemini web üzerinden tetikler (Yönetici aracı)."""
    if request.method == 'POST':
        file_path = request.POST.get('file_path', '').strip()

        if not file_path:
            return JsonResponse({'success': False, 'message': 'Lütfen Excel dosyasının tam yolunu girin.'}, status=400)

        try:
            call_command('load_stok', file_path)
            return JsonResponse({'success': True, 'message': f'Stok verileri ({file_path}) başarıyla yüklendi/güncellendi.'})

        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Stok yüklenirken hata oluştu: {e}'}, status=500)

    return JsonResponse({'success': False, 'message': 'Geçersiz metot.'}, status=400)
# --- AJAX / Yardımcı Fonksiyonlar ---

def get_last_sayim_info(benzersiz_id):
    """Verilen benzersiz ID'ye ait son sayım bilgisini çeker."""
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
# ⭐ OPTİMİZE EDİLMİŞ AKILLI ARAMA FONKSİYONU (views.py)
# ####################################################################################

@csrf_exempt
def ajax_akilli_stok_ara(request):
    """
    AJAX ile akıllı arama yapar (Seri No/Barkod öncelikli, Parti No/Renk varsa Stok Kodu Tahmini yapar, sonra varyant listeler).
    """
    if request.method != 'GET':
        return JsonResponse({'success': False, 'message': 'Geçersiz metot.'}, status=400)

    # Giriş parametrelerini al
    seri_no_raw = request.GET.get('seri_no', '')
    stok_kod_raw = request.GET.get('stok_kod', '')
    parti_no_raw = request.GET.get('parti_no', '')
    renk_raw = request.GET.get('renk', '')
    depo_kod_raw = request.GET.get('depo_kod', 'MERKEZ')
    barkod_ham_veri_raw = request.GET.get('barkod_ham_veri', '')


    # Verileri standartlaştır
    seri_no = standardize_id_part(seri_no_raw)
    stok_kod = standardize_id_part(stok_kod_raw)
    parti_no = standardize_id_part(parti_no_raw)
    renk = standardize_id_part(renk_raw)
    depo_kod_s = standardize_id_part(depo_kod_raw)
    barkod_ham_veri = standardize_id_part(barkod_ham_veri_raw)


    # 🚀 HİBRİT GÜÇLENDİRME: Seri No boşsa, Barkod Ham Verisini kullan.
    if seri_no == 'YOK' and barkod_ham_veri != 'YOK':
        seri_no = barkod_ham_veri
        if stok_kod == 'YOK':
            stok_kod = barkod_ham_veri


    response_data = {
        'found': False,
        'stok_kod': stok_kod,
        'parti_no': parti_no,
        'renk': renk,
        'parti_varyantlar': [],
        'renk_varyantlar': [],
        'urun_bilgi': 'Stok kodu veya Seri No girin...',
        'last_sayim': 'Bilinmiyor'
    }

    malzeme = None

    # --- 1. Öncelik: Seri No Arama (Seri No veya Barkod Ham Verisi varsa) ---
    if seri_no != 'YOK' and len(seri_no) >= 3:
        try:
            malzeme = Malzeme.objects.filter(
                seri_no=seri_no,
                lokasyon_kodu=depo_kod_s
            ).first()

            if malzeme:
                response_data['found'] = True
                response_data['stok_kod'] = malzeme.malzeme_kodu
                response_data['parti_no'] = malzeme.parti_no
                response_data['renk'] = malzeme.renk
                response_data['urun_bilgi'] = f"Seri No ile bulundu: {malzeme.malzeme_adi} ({malzeme.olcu_birimi}). Sistem: {malzeme.sistem_stogu:.2f}"
                response_data['sistem_stok'] = f"{malzeme.sistem_stogu:.2f}" 

                last_sayim_info = get_last_sayim_info(malzeme.benzersiz_id)
                if last_sayim_info:
                    response_data['last_sayim'] = f"{last_sayim_info['tarih']} - {last_sayim_info['personel']}"

                return JsonResponse(response_data)
        except Exception:
            pass

    # --- YENİ EKLENEN KRİTİK BLOK: Parti No'dan Stok Kodu Tahmini ---
    # Stok kodu yoksa, ancak Parti No ve/veya Renk varsa, Stok Kodunu bulmaya çalış
    if stok_kod == 'YOK' and parti_no != 'YOK':
        tahmin_filtresi = {
            'parti_no': parti_no,
            'lokasyon_kodu': depo_kod_s
        }
        if renk != 'YOK':
            tahmin_filtresi['renk'] = renk

        tahmin_malzeme = Malzeme.objects.filter(**tahmin_filtresi).values('malzeme_kodu').first()

        if tahmin_malzeme:
            # Tahmin başarılı: Stok Kodunu güncelledik, şimdi tam eşleşme arayacak.
            stok_kod = standardize_id_part(tahmin_malzeme['malzeme_kodu'])
            response_data['stok_kod'] = stok_kod
            response_data['parti_no'] = parti_no # Parti no'yu da koruyoruz
            response_data['renk'] = renk # Rengi de koruyoruz
            response_data['urun_bilgi'] = f"Parti No ({parti_no}) ile Stok Kodu **{stok_kod}** tahmin edildi. Tam eşleşme aranıyor..."
            # Not: Kod akışı, Stok Kodu artık dolu olduğu için doğrudan Öncelik 2'ye geçer.


    # --- 2. Öncelik: Parti No / Tam Eşleşme Arama (Stok Kodu tahmin edilmiş olabilir) ---
    if stok_kod != 'YOK' and parti_no != 'YOK' and renk != 'YOK':
        benzersiz_id = generate_unique_id(stok_kod, parti_no, depo_kod_s, renk)
        malzeme = Malzeme.objects.filter(benzersiz_id=benzersiz_id).first()

        if malzeme:
            response_data['found'] = True
            response_data['stok_kod'] = malzeme.malzeme_kodu 
            response_data['urun_bilgi'] = f"Parti No ile tam eşleşme: {malzeme.malzeme_adi} ({malzeme.olcu_birimi}). Sistem: {malzeme.sistem_stogu:.2f}"
            response_data['sistem_stok'] = f"{malzeme.sistem_stogu:.2f}" 

            last_sayim_info = get_last_sayim_info(malzeme.benzersiz_id)
            if last_sayim_info:
                response_data['last_sayim'] = f"{last_sayim_info['tarih']} - {last_sayim_info['personel']}"

            return JsonResponse(response_data)


    # --- 3. Öncelik: Stok Kodu Bazlı Varyant Listeleme (Hız Optimizasyonu) ---
    # Stok kodu tahmin edildiyse, bu blok varyantları listeleyecektir.
    if stok_kod != 'YOK' and len(stok_kod) >= 3:
        try:
            varyant_data = Malzeme.objects.filter(
                malzeme_kodu=stok_kod,
                lokasyon_kodu=depo_kod_s
            ).values('parti_no', 'renk').distinct()
        except Exception as e:
            print(f"Varyant Listesi Çekme Hatası: {e}")
            varyant_data = []

        parti_set = set()
        renk_set = set()

        for item in varyant_data:
            if item.get('parti_no'):
                parti_set.add(item['parti_no'])
            if item.get('renk'):
                renk_set.add(item['renk'])

        parti_varyantlar = sorted(list(parti_set))
        renk_varyantlar = sorted(list(renk_set))

        response_data['parti_varyantlar'] = parti_varyantlar
        response_data['renk_varyantlar'] = renk_varyantlar
        response_data['urun_bilgi'] = f"Stok Kodu **{stok_kod}**'a ait varyantlar listelendi. Tam eşleşme sağlanamadı."


    return JsonResponse(response_data)

# ####################################################################################
# ⭐ KRİTİK REVİZYON: ajax_sayim_kaydet (Konum Takibi Eklendi)
# ####################################################################################

@csrf_exempt
def ajax_sayim_kaydet(request, sayim_emri_id):
    """
    AJAX ile sayım miktarını kaydeder; yeni stokları otomatik ekler ve mevcut miktarın üzerine atomik olarak ekler.
    Ayrıca kullanıcının anlık konum bilgisini (lat/lon) kaydeder.
    """
    if request.method == 'POST':
        start_time = time.time()
        depo_kod_s = 'YOK'

        try:
            data = json.loads(request.body)
            stok_kod_raw = data.get('stok_kod', '')
            parti_no_raw = data.get('parti_no', '')
            renk_raw = data.get('renk', '')
            miktar_str = data.get('miktar', '')
            depo_kod_raw = data.get('depo_kod', 'MERKEZ')
            personel_adi = data.get('personel_adi', 'MISAFIR')
            
            # ⭐ YENİ EKLENEN KRİTİK ALANLAR: Konum verilerini yakala
            lat = data.get('lat', 'YOK')
            lon = data.get('lon', 'YOK')
            loc_hata = data.get('loc_hata', '')

            stok_kod = standardize_id_part(stok_kod_raw)
            parti_no = standardize_id_part(parti_no_raw)
            renk = standardize_id_part(renk_raw)
            depo_kod_s = standardize_id_part(depo_kod_raw)

            if stok_kod == 'YOK' or not miktar_str:
                return JsonResponse({'success': False, 'message': 'Stok Kodu ve Miktar gerekli.'}, status=400)

            try:
                miktar = float(miktar_str)
                if miktar < 0: raise ValueError
            except ValueError:
                return JsonResponse({'success': False, 'message': 'Miktar geçerli bir sayı olmalıdır.'}, status=400)

            benzersiz_id = generate_unique_id(stok_kod, parti_no, depo_kod_s, renk)
            malzeme = Malzeme.objects.filter(benzersiz_id=benzersiz_id).first()

            # --- YENİ STOK EKLEME ---
            if not malzeme:
                malzeme = Malzeme.objects.create(
                    malzeme_kodu=stok_kod,
                    parti_no=parti_no,
                    renk=renk,
                    lokasyon_kodu=depo_kod_s,
                    malzeme_adi=f"Yeni Stok {stok_kod}",
                    olcu_birimi="ADET",
                    sistem_stogu=0.0,
                    birim_fiyat=0.0,
                    benzersiz_id=benzersiz_id
                )

            # NOTE: Konum verileri, ilk oluşturma (created) veya güncelleme sırasında set edilmelidir.
            defaults = {
                'sayilan_stok': 0.0, 
                'personel_adi': personel_adi,
                # ⭐ KONUM VERİLERİ (Defaults'a eklendi)
                'latitude': lat, 
                'longitude': lon, 
                'loc_hata': loc_hata
            }
            mevcut_kayit, created = SayimDetay.objects.get_or_create(
                sayim_emri_id=sayim_emri_id,
                benzersiz_malzeme=malzeme,
                defaults=defaults
            )

            # Atomik Miktar Ekleme: Veritabanı seviyesinde toplama yapar, Race Condition'ı önler
            if created:
                # Yeni oluşturulduysa
                mevcut_kayit.sayilan_stok = miktar
                mevcut_kayit.saniye_stamp = time.time() - start_time
                # Konum verileri defaults'tan geldiği için sadece save et
                mevcut_kayit.save()
            else:
                # Mevcutsa F() ile miktarın üzerine ekler (Atomik işlem)
                SayimDetay.objects.filter(pk=mevcut_kayit.pk).update(
                    sayilan_stok=F('sayilan_stok') + miktar,
                    guncellenme_tarihi=timezone.now(),
                    saniye_stamp=time.time() - start_time,
                    personel_adi=personel_adi,
                    # ⭐ KONUM GÜNCELLEME: Her sayım eklemede konumu güncelle
                    latitude=lat,
                    longitude=lon,
                    loc_hata=loc_hata,
                )
                # Güncel toplam miktarı alabilmek için kaydı DB'den tazeler
                mevcut_kayit.refresh_from_db()

            yeni_toplam_miktar = mevcut_kayit.sayilan_stok

            fark = yeni_toplam_miktar - malzeme.sistem_stogu

            # --- Hız Hesaplama ---
            try:
                son_kayit_tarihi = SayimDetay.objects.filter(
                    sayim_emri_id=sayim_emri_id,
                    personel_adi=personel_adi
                ).exclude(guncellenme_tarihi__isnull=True).aggregate(Max('guncellenme_tarihi'))

                if son_kayit_tarihi['guncellenme_tarihi__max']:
                    son_tarih = son_kayit_tarihi['guncellenme_tarihi__max']
                    kayit_arasi_saniye = (timezone.now() - son_tarih).total_seconds()
                    if kayit_arasi_saniye > 3600 or kayit_arasi_saniye < 0:
                        kayit_arasi_saniye = 0.0
                    else:
                        kayit_arasi_saniye = 0.0
                else:
                    kayit_arasi_saniye = 0.0
            except Exception:
                kayit_arasi_saniye = 0.0

            hiz_mesaji = f"Hız: {kayit_arasi_saniye:.2f} sn. Fark: {fark:.2f}" if kayit_arasi_saniye > 0 else f"İlk Sayım Kaydı. Fark: {fark:.2f}"

            return JsonResponse({
                'success': True,
                'created': created,
                'message': f"Sayım kaydedildi/EKLEME YAPILDI. {hiz_mesaji}",
                'fark': f"{fark:.2f}",
                'sistem_stok': f"{malzeme.sistem_stogu:.2f}",
                'yeni_miktar': f"{yeni_toplam_miktar:.2f}",
                'hiz_saniye': f"{kayit_arasi_saniye:.2f}"
            })

        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Beklenmedik bir hata oluştu: {e}'}, status=500)

@csrf_exempt
@require_POST
def gemini_ocr_analiz(request):
    # ... (Gemini OCR Analiz Kodu) ...
    # Kodu önceki yanıtınızdakiyle aynı tutuyorum, ancak burada çok uzun olduğu için kısaltıldı.
    pass

@csrf_exempt
def export_excel(request, pk):
    # ... (Excel Dışa Aktarma Kodu) ...
    pass

@csrf_exempt
def export_mutabakat_excel(request, pk):
    # ... (Mutabakat Excel Kodu) ...
    pass

# --- ⭐ ÖZEL YÖNETİM PANELİ VE GİRİŞ MANTIĞI ⭐ ---

# 1. Özel Yönetim Girişi View'ları
REPORT_PASSWORD = os.environ.get('REPORT_PASSWORD', 'SAYIMYENI2025') 

class OzelAdminLoginView(TemplateView):
    """Özel Yönetim Paneli için şifre giriş ekranı."""
    template_name = 'sayim/ozel_admin_login.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.session.get('ozel_admin_yetki'):
             return redirect('ozel_yonetim_paneli') 
        return context

@csrf_exempt
def check_ozel_admin_password(request):
    """Özel şifreyi kontrol eder ve başarılıysa session açar."""
    if request.method == 'POST':
        submitted_password = request.POST.get('password', '').strip()
        settings_password = os.environ.get('REPORT_PASSWORD', 'SAYIMYENI2025') 
        
        if submitted_password == settings_password:
            request.session['ozel_admin_yetki'] = True
            messages.success(request, "Yönetici girişi başarılı. Hoş geldiniz!")
            return redirect('ozel_yonetim_paneli') 
        else:
            messages.error(request, "Yanlış şifre! Erişim reddedildi.")
            return redirect('ozel_admin_login') 
    
    return redirect('ozel_admin_login') 

class OzelYonetimPanelView(ListView):
    """
    Özel Yönetim Paneli ana ekranı (Sayım Emirlerini listeler).
    """
    model = SayimEmri
    template_name = 'sayim/ozel_yonetim_paneli.html' 
    context_object_name = 'emirler'
    ordering = ['-tarih']

    def dispatch(self, request, *args, **kwargs):
        # Yetki kontrolü (sadece oturumda yetki varsa izin ver)
        if not request.session.get('ozel_admin_yetki'):
            return redirect('ozel_admin_login') 
        return super().dispatch(request, *args, **kwargs)


# 2. Django Admin Şifre Sorununu Çözen KESİN FONKSİYON
@csrf_exempt
@transaction.atomic
def admin_kurulum_final(request):
    """
    KESİN ÇÖZÜM: Admin kullanıcısını oluşturur (yoksa) veya şifresini garantili sıfırlar.
    Bu fonksiyonu çalıştırdıktan sonra HEMEN views.py ve urls.py'dan siliniz.
    """
    try:
        User = get_user_model()
        ADMIN_USERNAME = 'admin'
        ADMIN_PASSWORD = 'SAYIMYENI2025!'

        # 1. Kullanıcıyı bul veya oluştur (get_or_create ile)
        user, created = User.objects.get_or_create(
            username=ADMIN_USERNAME,
            defaults={
                'email': 'admin@example.com',
                'is_staff': True,
                'is_superuser': True,
                'is_active': True,
            }
        )

        # 2. Şifreyi set_password ile ayarla ve kaydet (Hashing garantisi)
        user.set_password(ADMIN_PASSWORD)
        user.is_staff = True
        user.is_superuser = True
        user.save() 

        if created:
            message = f"✅ YENİ YÖNETİCİ KULLANICISI BAŞARIYLA OLUŞTURULDU! Kullanıcı: {ADMIN_USERNAME}, Şifre: {ADMIN_PASSWORD}. Lütfen şimdi Admin sayfasına gidin."
        else:
            message = f"✅ YÖNETİCİ KULLANICISI ({ADMIN_USERNAME}) ŞİFRESİ BAŞARIYLA SIFIRLANDI! Yeni Şifre: {ADMIN_PASSWORD}. Lütfen şimdi Admin sayfasına gidin."

        return HttpResponse(message, status=200)
    
    except Exception as e:
        return HttpResponse(f"❌ KRİTİK VERİTABANI HATASI: Yönetici kurulumu yapılamadı. Hata: {e}", status=500)