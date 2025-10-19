# -*- coding: utf-8 -*-
import json
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

# Gemini ve OCR kütüphaneleri
from google import genai
from google.genai.errors import APIError
from PIL import Image
import io

# Barkod/QR okuma kütüphanesi
from pyzbar.pyzbar import decode
import base64

# --- Global Kullanıcı Değişkeni ---
CURRENT_USER = ""

# --- Örnek: Sayım Emirleri, Performans, Rapor vs View'ları ---
class SayimEmirleriListView(View):
    def get(self, request):
        return render(request, 'sayim_emirleri_list.html')

class SayimEmriCreateView(View):
    def get(self, request):
        return render(request, 'yeni_sayim_emri.html')

class PersonelLoginView(View):
    def get(self, request, sayim_emri_id, depo_kodu):
        return render(request, 'personel_login.html')

def set_personel_session(request):
    return JsonResponse({"status": "ok"})

# --- Gemini OCR ve görsel işleme endpoint ---
@csrf_exempt
def gemini_parti_oku(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            image_base64 = data.get("image_base64")
            if not image_base64:
                return JsonResponse({"status": "error", "message": "image_base64 eksik"})

            image_data = base64.b64decode(image_base64)
            image = Image.open(io.BytesIO(image_data))

            # Gemini OCR örnek çağrısı (mevcut kodun bozulmayacak)
            # response = genai.ocr_function(image)
            response = {"dummy": "OCR sonucu burada"}

            return JsonResponse({"status": "ok", "ocr_result": response})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)})

    return JsonResponse({"status": "error", "message": "Sadece POST desteklenir."})

# --- Barkod/QR okuma endpoint ---
@csrf_exempt
def ajax_barkod_okuma(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            barkod = data.get("barkod", None)
            image_base64 = data.get("image_base64", None)

            result = {}

            if barkod:
                result['barkod'] = barkod
                result['status'] = "ok"
                result['message'] = "Barkod alındı."
            elif image_base64:
                image_data = base64.b64decode(image_base64)
                image = Image.open(io.BytesIO(image_data))
                decoded_objects = decode(image)

                if decoded_objects:
                    result['barkod'] = decoded_objects[0].data.decode("utf-8")
                    result['status'] = "ok"
                    result['message'] = "Görselden barkod okundu."
                else:
                    result['status'] = "error"
                    result['message'] = "Barkod/QR bulunamadı."
            else:
                result['status'] = "error"
                result['message'] = "Barkod veya görsel sağlanmadı."

            return JsonResponse(result)

        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)})

    return JsonResponse({"status": "error", "message": "Sadece POST desteklenir."})

# --- Diğer view fonksiyonları ---
def ajax_sayim_kaydet(request, sayim_emri_id):
    return JsonResponse({"status": "ok", "message": "Kayıt tamam"})

def ajax_akilli_stok_ara(request):
    return JsonResponse({"status": "ok", "results": []})
