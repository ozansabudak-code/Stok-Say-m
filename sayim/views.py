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
from django.views.generic import ListView, CreateView, DetailView, TemplateView
from django.urls import reverse_lazy
# F ifadesini kullanabilmek için F eklendi
from django.db import connection, transaction
from django.db.models import Max, F # <--- F BURAYA EKLENDİ
from django.utils import timezone
from django.core.management import call_command


# Third-party Imports
from PIL import Image
import pandas as pd
import pytesseract # OCR için gerekli kütüphane
# Temizlenmiş ve doğru kod
from PIL import Image, ImageFile

# Gemini (Google GenAI) Imports
from google import genai
from google.genai.errors import APIError

# Local Imports
# (Malzeme modelinde 'seri_no' alanı olması beklenmektedir)
from .models import SayimEmri, Malzeme, SayimDetay, standardize_id_part, generate_unique_id
from .forms import SayimGirisForm

# --- GEMINI SABİTLERİ (DEĞİŞMEDİ) ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

try:
    if GEMINI_API_KEY:
        client = genai.Client(api_key=GEMINI_API_KEY)
        GEMINI_AVAILABLE = True
    else:
        GEMINI_AVAILABLE = False
except Exception:
    GEMINI_AVAILABLE = False

# Resim dosyalarının okunmasını desteklemek için
ImageFile.LOAD_TRUNCATED_IMAGES = True


# --- GÖRÜNÜMLER (VIEWS) (DEĞİŞMEDİ) ---
class SayimEmirleriListView(ListView):
    model = SayimEmri
    template_name = 'sayim/sayim_emirleri.html'
    context_object_name = 'emirler'
    ordering = ['-tarih']

class SayimEmriCreateView(CreateView):
    model = SayimEmri
    fields = ['ad']
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
        return context

@csrf_exempt
def set_personel_session(request):
    if request.method == 'POST':
        personel_adi = request.POST.get('personel_adi', '').strip().upper()
        sayim_emri_id = request.POST.get('sayim_emri_id')
        depo_kodu = request.POST.get('depo_kodu')

        if personel_adi:
            request.session['current_user'] = personel_adi
            return redirect('sayim_giris', pk=sayim_emri_id, depo_kodu=depo_kodu)

        return redirect('depo_secim', sayim_emri_id=sayim_emri_id)

    return redirect('sayim_emirleri')

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
# --- RAPORLAMA, ONAY VE ANALİZ VIEW'LARI (DEĞİŞMEDİ) ---

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
            # SQL sorgusu: Personelleri al.
            query = f"""
                SELECT
                    personel_adi,
                    COUNT(id) AS toplam_kayit,
                    -- Bu süreyi hesapla: MAX(tarih) - MIN(tarih)
                    CAST((JULIANDAY(MAX(guncellenme_tarihi)) - JULIANDAY(MIN(guncellenme_tarihi))) * 86400.0 AS REAL) AS toplam_saniye
                FROM sayim_sayimdetay
                WHERE sayim_emri_id = {sayim_emri_id}
                GROUP BY personel_adi
            """

            df = pd.read_sql_query(query, connection)
            analiz_list = []

            for _, row in df.iterrows():
                toplam_saniye = row['toplam_saniye']
                toplam_kayit = row['toplam_kayit']

                # --- Ortalama Süre Hesaplama ve Durum Etiketleme ---
                if toplam_kayit > 1:
                    # N kayıt için N-1 aralık vardır.
                    ortalama_sure_sn = toplam_saniye / (toplam_kayit - 1)

                    if ortalama_sure_sn > 3600:
                        # Ortalama hız 1 saatin üzerindeyse, bu verinin hatalı/aykırı olduğunu varsayalım.
                        etiket = 'Aykırı Veri ( > 1 Saat/Kayıt)'
                        ortalama_sure_sn = float('inf') # Sıralama için sonsuz değer ata
                    else:
                        dakika = int(ortalama_sure_sn // 60)
                        saniye_kalan = int(ortalama_sure_sn % 60)
                        etiket = f"{dakika:02d}:{saniye:02d}"

                else:
                    # Tek kayıt varsa hız hesaplanamaz.
                    ortalama_sure_sn = float('inf') # Sıralamada sona atmak için sonsuz değer
                    etiket = 'Yetersiz Kayıt (N=1)'

                analiz_list.append({
                    'personel': row['personel_adi'],
                    'toplam_kayit': toplam_kayit,
                    'toplam_sure_sn': f"{toplam_saniye:.2f}",
                    'ortalama_sure_formatli': etiket,
                    'ortalama_sure_sn': ortalama_sure_sn # Sıralama için ham değeri tut
                })

            # Analiz listesini Ortalama süreye göre sırala (Sonsuz olanlar sona atılır)
            analiz_list.sort(key=lambda x: x['ortalama_sure_sn'])

            # Gösterim için 'inf' olanları '0.00' veya önceki etiketiyle güncelle
            for item in analiz_list:
                if item['ortalama_sure_sn'] == float('inf'):
                    item['ortalama_sure_sn'] = '0.00'
                else:
                    item['ortalama_sure_sn'] = f"{item['ortalama_sure_sn']:.2f}"

            context['analiz_data'] = analiz_list

        except Exception as e:
            context['analiz_data'] = []
            context['hata'] = f"Performans analizi hatası: {e}"

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
            return JsonResponse({'success': False, 'message': f'Stok yüklenirken hata oluştu: {e}'})

    return JsonResponse({'success': False, 'message': 'Geçersiz metot.'}, status=400)
# --- AJAX / Yardımcı Fonksiyonlar (DEĞİŞMEDİ) ---

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
# ⭐ OPTİMİZE EDİLMİŞ AKILLI ARAMA FONKSİYONU (Barkod Entegrasyonu Eklendi)
# ####################################################################################

@csrf_exempt
def ajax_akilli_stok_ara(request):
    """
    AJAX ile akıllı arama yapar (Seri No/Barkod öncelikli, Parti No yedekli, optimize edilmiş varyant listeleme).
    """
    if request.method != 'GET':
        return JsonResponse({'success': False, 'message': 'Geçersiz metot.'}, status=400)
    
    # Giriş parametrelerini al
    seri_no_raw = request.GET.get('seri_no', '')
    stok_kod_raw = request.GET.get('stok_kod', '')
    parti_no_raw = request.GET.get('parti_no', '')
    renk_raw = request.GET.get('renk', '')
    depo_kod_raw = request.GET.get('depo_kod', 'MERKEZ')
    # 🚀 YENİ: Hem manuel hem de Gemini'den gelen barkod ham verisi
    barkod_ham_veri_raw = request.GET.get('barkod_ham_veri', '') 


    # Verileri standartlaştır
    seri_no = standardize_id_part(seri_no_raw)
    stok_kod = standardize_id_part(stok_kod_raw)
    parti_no = standardize_id_part(parti_no_raw)
    renk = standardize_id_part(renk_raw)
    depo_kod_s = standardize_id_part(depo_kod_raw)
    barkod_ham_veri = standardize_id_part(barkod_ham_veri_raw) # Standartlaştır


    # 🚀 HİBRİT GÜÇLENDİRME: Seri No boşsa, Barkod Ham Verisini kullan.
    # Bu, QR/Barkod okuyucudan gelen tek bir metin dizisinin Seri No gibi davranmasını sağlar.
    if seri_no == 'YOK' and barkod_ham_veri != 'YOK':
        seri_no = barkod_ham_veri
        # Eğer stok kodu da boşsa, ham barkod verisini stok kodu olarak da dene
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
            # Seri No aramasında tam eşleşme arıyoruz
            malzeme = Malzeme.objects.filter(
                seri_no=seri_no, 
                lokasyon_kodu=depo_kod_s
            ).first()

            if malzeme:
                # Seri No ile bulundu, Tam eşleşme olduğundan hemen dönüyoruz.
                response_data['found'] = True
                response_data['stok_kod'] = malzeme.malzeme_kodu
                response_data['parti_no'] = malzeme.parti_no
                response_data['renk'] = malzeme.renk
                response_data['urun_bilgi'] = f"Seri No ile bulundu: {malzeme.malzeme_adi} ({malzeme.olcu_birimi}). Sistem: {malzeme.sistem_stogu:.2f}"
                
                last_sayim_info = get_last_sayim_info(malzeme.benzersiz_id)
                if last_sayim_info:
                    response_data['last_sayim'] = f"{last_sayim_info['tarih']} - {last_sayim_info['personel']}"
                
                return JsonResponse(response_data)
        except Exception:
            # Seri No aramasında bir hata olursa (ör. seri_no alanı yoksa veya veritabanı hatası)
            pass 

    # --- 2. Öncelik: Parti No / Tam Eşleşme Arama (Seri No başarısız olduysa) ---
    if stok_kod != 'YOK' and parti_no != 'YOK' and renk != 'YOK':
        benzersiz_id = generate_unique_id(stok_kod, parti_no, depo_kod_s, renk)
        malzeme = Malzeme.objects.filter(benzersiz_id=benzersiz_id).first()
        
        if malzeme:
            # Tam eşleşme ile bulundu.
            response_data['found'] = True
            response_data['urun_bilgi'] = f"Parti No ile tam eşleşme: {malzeme.malzeme_adi} ({malzeme.olcu_birimi}). Sistem: {malzeme.sistem_stogu:.2f}"

            last_sayim_info = get_last_sayim_info(benzersiz_id)
            if last_sayim_info:
                response_data['last_sayim'] = f"{last_sayim_info['tarih']} - {last_sayim_info['personel']}"

            return JsonResponse(response_data)


    # --- 3. Öncelik: Stok Kodu Bazlı Varyant Listeleme (Hız Optimizasyonu) ---
    # Eğer Seri No veya Tam Eşleşme bulunamadıysa, Stok Koduna ait varyantları listeleriz.
    if stok_kod != 'YOK' and len(stok_kod) >= 3:
        
        # ⭐ OPTİMİZASYON: Parti No ve Renk listesini tek sorguda çekme
        try:
            varyant_data = Malzeme.objects.filter(
                malzeme_kodu=stok_kod, 
                lokasyon_kodu=depo_kod_s
            ).values('parti_no', 'renk').distinct() # Tek sorgu ile hem parti hem renk çekilir
        except Exception as e:
            # Kritik DB hatası durumunda loglama yapılabilir.
            print(f"Varyant Listesi Çekme Hatası: {e}")
            varyant_data = []

        parti_set = set()
        renk_set = set()
        
        # Python tarafında set'lere ayırma (Çok hızlı)
        for item in varyant_data:
            if item.get('parti_no'):
                parti_set.add(item['parti_no'])
            if item.get('renk'):
                renk_set.add(item['renk'])

        # Sonuçları hazırlama
        parti_varyantlar = sorted(list(parti_set))
        renk_varyantlar = sorted(list(renk_set))
        
        response_data['parti_varyantlar'] = parti_varyantlar
        response_data['renk_varyantlar'] = renk_varyantlar
        response_data['urun_bilgi'] = "Seri/Parti eşleşmedi. Stok koduna ait varyantlar listelendi. Yeni stok olabilir."


    return JsonResponse(response_data)

# ####################################################################################
# ⭐ KRİTİK REVİZYON: ajax_sayim_kaydet (Atomik Miktar Ekleme)
# ####################################################################################

@csrf_exempt
def ajax_sayim_kaydet(request, sayim_emri_id):
    """
    AJAX ile sayım miktarını kaydeder; yeni stokları otomatik ekler ve mevcut miktarın üzerine atomik olarak ekler.
    (Race Condition'ları önlemek için F ifadeleri kullanıldı.)
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

            mevcut_kayit, created = SayimDetay.objects.get_or_create(
                sayim_emri_id=sayim_emri_id,
                benzersiz_malzeme=malzeme,
                defaults={'sayilan_stok': 0.0, 'personel_adi': personel_adi}
            )

            # Atomik Miktar Ekleme: Veritabanı seviyesinde toplama yapar, Race Condition'ı önler
            if created:
                # Yeni oluşturulduysa, miktarı direk atar
                mevcut_kayit.sayilan_stok = miktar
                mevcut_kayit.saniye_stamp = time.time() - start_time
                mevcut_kayit.personel_adi = personel_adi
                mevcut_kayit.save()
            else:
                # Mevcutsa F() ile miktarın üzerine ekler (Atomik işlem)
                SayimDetay.objects.filter(pk=mevcut_kayit.pk).update(
                    sayilan_stok=F('sayilan_stok') + miktar,
                    guncellenme_tarihi=timezone.now(), # Güncelleme tarihini manuel olarak ayarla
                    saniye_stamp=time.time() - start_time,
                    personel_adi=personel_adi
                )
                # Güncel toplam miktarı alabilmek için kaydı DB'den tazeler
                mevcut_kayit.refresh_from_db()

            yeni_toplam_miktar = mevcut_kayit.sayilan_stok # Artık atomik olarak güncel değerimiz var

            fark = yeni_toplam_miktar - malzeme.sistem_stogu
            
            # --- Hız Hesaplama (Ekstra sorgu, ancak performansa büyük etkisi yok) ---
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

# ####################################################################################
# ⭐ GÜNCELLENDİ: gemini_parti_oku (Barkod Ham Veri Çıkarma Eklendi)
# ####################################################################################

@csrf_exempt
def gemini_parti_oku(request):
    """
    Gemini Vision kullanarak etiket fotoğrafından Seri No, Stok Kodu, Parti No, Varyant ve BARKOD HAM METNİ okur.
    """
    if not GEMINI_AVAILABLE:
        return JsonResponse({'success': False, 'message': 'Gemini API anahtarı ayarlanmamış.'}, status=503)

    if request.method == 'POST' and request.FILES.get('image'):

        uploaded_file = request.FILES['image']

        # YÜKSEK ÇÖZÜNÜRLÜKLÜ GÖRSELİ OKUMA VE ÖN İŞLEME
        try:
            image_data = uploaded_file.read()
            img_original = Image.open(BytesIO(image_data))
            
            # Yeniden Boyutlandırma ve Sıkıştırma Ayarları
            MAX_SIZE = (1500, 1500) 
            JPEG_QUALITY = 85
            
            img_original.thumbnail(MAX_SIZE, Image.Resampling.LANCZOS)
            
            buffer_compressed = BytesIO()
            if img_original.mode in ('RGBA', 'P'):
                img_original = img_original.convert('RGB')
            
            img_original.save(buffer_compressed, format="JPEG", quality=JPEG_QUALITY)
            buffer_compressed.seek(0)
            
            if buffer_compressed.getbuffer().nbytes > 5 * 1024 * 1024:
                return JsonResponse({'success': False, 'message': 'Görsel ön işleme sonrası bile 5MB sınırını aşıyor.'}, status=400)
            
            img_for_gemini = Image.open(buffer_compressed)
            img_tesseract = img_for_gemini.convert('L') 

            # PROMPT GÜNCELLENDİ (Barkod Ham Veri Eklendi)
            prompt = (
                "Bu bir stok sayım etiketinin fotoğrafıdır. Göreviniz Seri Numarası, Stok Kodu, Parti Numarası, Varyant (renk) **VE etiket üzerindeki QR kod/barkodun kodladığı ham metni** okumaktır. "
                "Önemli Kurallar: 1. Tüm değerleri etiket üzerinde gördüğünüz ham metin olarak döndürün. 2. Eğer bir alan (özellikle Varyant veya Barkod Ham Veri) etikette kesinlikle yoksa veya okunamıyorsa, değeri sadece 'YOK' olarak döndürün. 3. Tüm yanıtı SADECE aşağıdaki JSON şemasına uygun döndürün."
            )

            # SCHEMA GÜNCELLENDİ (Barkod Ham Veri Eklendi)
            response_schema = {
                "type": "OBJECT",
                "properties": {
                    "Seri No": {"type": "STRING"},
                    "Stok Kodu": {"type": "STRING"},
                    "Parti No": {"type": "STRING"},
                    "Varyant": {"type": "STRING"},
                    "Barkod Ham Veri": {"type": "STRING"} # <<< YENİ ALAN
                }
            }

            # --- 1. Adım: Gemini ile Oku (JSON Zorlaması) ---
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=[prompt, img_for_gemini],
                config={
                    "response_mime_type": "application/json",
                    "response_schema": response_schema
                }
            )

            try:
                json_string = response.text.strip()
                if json_string.startswith("```json"):
                    json_string = json_string.strip("```json").strip()
                if json_string.endswith("```"):
                    json_string = json_string.strip("```").strip()

                parsed_data = json.loads(json_string)

            except json.JSONDecodeError as e:
                return JsonResponse({'success': False, 'message': f'Gemini yanıtı çözülemedi. Lütfen etiketi net çekin. Hata: {e}', 'raw_text': response.text}, status=500)

            # Seri No ve diğer bilgileri çek
            seri_no_raw = parsed_data.get('Seri No', '')
            stok_kod_raw = parsed_data.get('Stok Kodu', '')
            parti_no_raw = parsed_data.get('Parti No', '')
            varyant_raw = parsed_data.get('Varyant', '')
            barkod_ham_veri_raw = parsed_data.get('Barkod Ham Veri', '') # <<< YENİ VERİ

            seri_no = standardize_id_part(seri_no_raw)
            stok_kod = standardize_id_part(stok_kod_raw)
            parti_no = standardize_id_part(parti_no_raw)
            varyant = varyant_raw.strip().upper()
            barkod_ham_veri = standardize_id_part(barkod_ham_veri_raw) # Standartlaştır


            # --- 2. Adım: Varyant Eksikse OCR ile Görüntüyü Taramayı Dene (Yedekleme) ---
            if not varyant or varyant in ['...', '', 'YOK']:
                text = pytesseract.image_to_string(img_tesseract, lang='tur').upper()
                if 'VARYANT' in text:
                    try:
                        start_index = text.find('VARYANT')
                        sub_text = text[start_index:].split('\n')[0].split(':')[1].strip() if ':' in text[start_index:].split('\n')[0] else text[start_index:].split('\n')[0].strip().replace('VARYANT', '').strip()

                        if len(sub_text) > 2 and sub_text not in ['...', 'BILINMIYOR', 'YOK']:
                            varyant = sub_text
                    except:
                        pass

            # Son kontrol ve standartlaştırma
            if not varyant or varyant in ['...', '']:
                 varyant = 'BILINMIYOR'
            else:
                 varyant = standardize_id_part(varyant)

            # Seri No boşsa, Barkod Ham Verisini kullanma önceliği (Eğer barkodun seri no/ürün kodu olduğu varsayılırsa)
            if seri_no == 'YOK' and barkod_ham_veri != 'YOK' and len(barkod_ham_veri) > 2:
                seri_no = barkod_ham_veri
            elif stok_kod == 'YOK' and barkod_ham_veri != 'YOK' and len(barkod_ham_veri) > 2:
                stok_kod = barkod_ham_veri


            return JsonResponse({
                'success': True,
                'seri_no': seri_no, # En çok eşleşme ihtimali olan değer
                'stok_kod': stok_kod,
                'parti_no': parti_no,
                'renk': varyant,
                'barkod_ham_veri': barkod_ham_veri, # Yeni: Eğer barkodun tek başına bir seri no/stok kodu olmadığı durumda kullanılabilir
                'message': f'Veri başarıyla okundu. Seri No: {seri_no}, Stok Kodu: {stok_kod}, Parti No: {parti_no}, Varyant: {varyant}'
            })

        except APIError as e:
            return JsonResponse({'success': False, 'message': f'Gemini API Hatası: {e}'}, status=500)
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Sunucu Hatası: {e}'}, status=500)

@csrf_exempt
def export_excel(request, pk):
    """Performans analizini Excel olarak dışa aktarır."""
    try:
        # Sayım emrini al
        sayim_emri = get_object_or_404(SayimEmri, pk=pk)
        sayim_emri_id = sayim_emri.pk

        # Veriyi çek
        df = pd.read_sql_query(f"""
            SELECT personel_adi, guncellenme_tarihi
            FROM sayim_sayimdetay
            WHERE sayim_emri_id = {sayim_emri_id}
        """, connection)

        if df.empty:
            return JsonResponse({'success': False, 'message': 'Veri bulunamadı.'}, status=404)

        analiz_list = []

        # Personel bazında analiz
        for personel, group in df.groupby('personel_adi'):
            group = group.sort_values('guncellenme_tarihi')
            if len(group) < 2:
                ortalama_sn = 0
                toplam_sure = 0
                toplam_kayit = len(group)
            else:
                farklar = group['guncellenme_tarihi'].diff().dt.total_seconds().dropna()
                ortalama_sn = farklar.mean()
                toplam_sure = farklar.sum()
                toplam_kayit = len(group)

            dakika, saniye = divmod(int(ortalama_sn), 60)
            analiz_list.append({
                'personel': personel,
                'toplam_kayit': toplam_kayit,
                'toplam_sure_sn': f"{toplam_sure:.2f}",
                'ortalama_sure_formatli': f"{dakika:02d}:{saniye:02d}" if toplam_kayit > 1 else "Yetersiz Kayıt",
                'ortalama_sure_sn': f"{ortalama_sn:.2f}"
            })

        # Excel çıktısı oluştur
        from io import BytesIO
        buffer = BytesIO()
        pd.DataFrame(analiz_list).to_excel(buffer, index=False)
        buffer.seek(0)

        response = HttpResponse(
            buffer,
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="performans_analizi_{sayim_emri.ad}.xlsx"'
        return response

    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Excel dışa aktarım hatası: {e}'}, status=500)

# --- views.py içerisindeki export_mutabakat_excel fonksiyonu (DEĞİŞMEDİ) ---
@csrf_exempt
def export_mutabakat_excel(request, pk):
    """Mutabakat raporunu Excel olarak dışa aktarır."""
    try:
        sayim_emri = get_object_or_404(SayimEmri, pk=pk)
        sayim_detaylari = SayimDetay.objects.filter(sayim_emri=sayim_emri).select_related('benzersiz_malzeme')
        tum_malzemeler = Malzeme.objects.all()

        rapor_list = []
        # Benzersiz ID'ye göre son sayım miktarlarını topla (Bu kısım zaten doğru çalışıyor olmalı)
        sayilan_miktarlar = {}
        for detay in sayim_detaylari:
             malzeme_id = detay.benzersiz_malzeme.benzersiz_id
             sayilan_miktarlar[malzeme_id] = sayilan_miktarlar.get(malzeme_id, 0.0) + detay.sayilan_stok


        for malzeme in tum_malzemeler:
            # 🚀 GÜÇLENDİRME: Float olmayan değerler için varsayılan 0.0 kullanma
            sayilan_mik = sayilan_miktarlar.get(malzeme.benzersiz_id, 0.0)
            sistem_mik = float(getattr(malzeme, 'sistem_stogu', 0.0) or 0.0)
            birim_fiyat = float(getattr(malzeme, 'birim_fiyat', 0.0) or 0.0)

            mik_fark = sayilan_mik - sistem_mik
            tutar_fark = mik_fark * birim_fiyat
            sistem_tutar = sistem_mik * birim_fiyat
            
            # Hata oluşmasını engelleyen NaN kontrolü
            mik_yuzde = (mik_fark / sistem_mik * 100) if sistem_mik and sistem_mik != 0 else 0

            rapor_list.append({
                'Stok Kodu': malzeme.malzeme_kodu,
                'Stok Adı': malzeme.malzeme_adi,
                'Parti No': malzeme.parti_no,
                'Renk': malzeme.renk,
                'Birim': malzeme.olcu_birimi,
                'Sistem Mik.': sistem_mik,
                'Sayım Mik.': sayilan_mik,
                'Mik. Fark': mik_fark,
                'Fark %': f"{mik_yuzde:.2f}", # Yüzdeyi formatla
                'Sistem Tutar (₺)': sistem_tutar,
                'Tutar Farkı (₺)': tutar_fark
            })

        import pandas as pd
        from io import BytesIO

        df = pd.DataFrame(rapor_list)
        
        # 🚀 KRİTİK: Boş veriden kaynaklanan Pandas/Excel hatalarını önle
        df = df.fillna(0) 

        buffer = BytesIO()
        df.to_excel(buffer, index=False)
        buffer.seek(0)

        from django.http import HttpResponse
        response = HttpResponse(
            buffer,
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="mutabakat_raporu_{sayim_emri.ad}.xlsx"'
        return response

    except Exception as e:
        # Hata olursa 500 dönmek yerine daha bilgilendirici bir hata mesajı döndür.
        return JsonResponse({'success': False, 'message': f'Mutabakat Excel dışa aktarım hatası: {e}'}, status=500)