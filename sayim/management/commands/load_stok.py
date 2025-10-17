import pandas as pd
from django.core.management.base import BaseCommand, CommandError
from sayim.models import Malzeme, standardize_id_part, generate_unique_id
from django.db import transaction # Toplu işlem için eklendi

class Command(BaseCommand):
    help = 'Belirtilen Excel dosyasından stok verilerini Malzemeler tablosuna yükler.'

    def add_arguments(self, parser):
        parser.add_argument('file_path', type=str, help='Yüklenecek Excel veya CSV dosyasının yolu')

    def handle(self, *args, **options):
        file_path = options['file_path']
        self.stdout.write(f"Dosya yolu: {file_path}")

        try:
            if file_path.lower().endswith(('.xlsx', '.xls')):
                df = pd.read_excel(file_path, header=0, sheet_name=0, na_filter=False, keep_default_na=True)
            elif file_path.lower().endswith('.csv'):
                df = pd.read_csv(file_path, header=0, encoding='iso-8859-9', na_filter=False, keep_default_na=True)
            else:
                raise CommandError("Desteklenmeyen dosya formatı. Lütfen .xlsx, .xls veya .csv kullanın.")
        
        except FileNotFoundError:
            raise CommandError(f"HATA: Dosya bulunamadı: {file_path}")
        except Exception as e:
            raise CommandError(f"Dosya okunurken problem oluştu: {e}")

        # 🚀 KRİTİK DÜZELTME: Sütunları, kullanıcının gönderdiği 0'dan 13'e kadar olan indekse göre EŞLEŞTİRME
        try:
            df_selected = pd.DataFrame({
                'seri_no': df.iloc[:, 0],                # 0: seri_no (Yeni Alan)
                'parti_no': df.iloc[:, 1],               # 1: Parti
                'lokasyon_kodu': df.iloc[:, 2],          # 2: Depo Kodu
                'depo_adi': df.iloc[:, 3],               # 3: Depo Adı
                'malzeme_kodu': df.iloc[:, 4],           # 4: Stok Kodu
                'malzeme_adi': df.iloc[:, 5],            # 5: Stok Adı
                'renk': df.iloc[:, 6],                   # 6: Renk 
                
                'sistem_stogu': df.iloc[:, 7],           # 7: Miktar (SAYISAL)
                'sistem_tutari_excel': df.iloc[:, 8],    # 8: Tutar (EXCEL'den okunacak, ancak kullanılmayacak)

                'birim_fiyat': df.iloc[:, 9],            # 9: Maliyet birim (SAYISAL)
                'olcu_birimi': df.iloc[:, 10],           # 10: Birim (Kg., Adet vb. METİN)

                'stok_grup': df.iloc[:, 11],             # 11: Grup
                'depo_sinif': df.iloc[:, 12],            # 12: Depo Sınıfı
                'barkod': df.iloc[:, 13],                # 13: barkod (Modelinizde barkod alanı varsa)
            })
            
        except IndexError as e:
            raise CommandError(f"Excel sütun indeksi hatası. Dosyanızdaki sütun sayısının en az 14 (0'dan 13'e) olduğundan emin olun. Hata: {e}")
        except Exception as e:
            raise CommandError(f"Veri dönüşüm hatası (İndeksleme sonrası): {e}")

        # Veriyi Django modeline yükleme (update_or_create kullanarak)
        success_count = 0
        
        # Sütunlarda boşluk olmaması için strip metodu
        def safe_float(value):
            if pd.isna(value) or value is None or str(value).strip() == '':
                return 0.0
            # Virgül yerine nokta kullanmak ve metinsel kirleticileri temizlemek için
            cleaned = str(value).strip().replace(',', '.')
            
            # Eğer değer Kg. gibi bir metin ise 0.0 döndür
            if any(char.isalpha() for char in cleaned):
                return 0.0 
                
            return float(cleaned)

        
        for index, row in df_selected.iterrows():
            try:
                malzeme_kodu_clean = standardize_id_part(row.get('malzeme_kodu'))
                
                if malzeme_kodu_clean == 'YOK':
                    continue 

                benzersiz_id_val = generate_unique_id(
                    malzeme_kodu_clean,
                    standardize_id_part(row.get('parti_no')),
                    standardize_id_part(row.get('lokasyon_kodu', 'MERKEZ')),
                    standardize_id_part(row.get('renk'))
                )
                
                seri_no_val = standardize_id_part(row.get('seri_no', 'YOK')) 

                # Sayısal alanlar artık özel temizleme fonksiyonu ile dönüştürülüyor
                sistem_stogu_val = safe_float(row.get('sistem_stogu'))
                birim_fiyat_val = safe_float(row.get('birim_fiyat'))
                
                # sistem_tutari Python'da hesaplanıyor
                sistem_tutari_val = sistem_stogu_val * birim_fiyat_val
                
                Malzeme.objects.update_or_create(
                    benzersiz_id=benzersiz_id_val,
                    defaults={
                        'malzeme_kodu': malzeme_kodu_clean,
                        'parti_no': standardize_id_part(row.get('parti_no')),
                        'lokasyon_kodu': standardize_id_part(row.get('lokasyon_kodu', 'MERKEZ')),
                        'depo_adi': str(row.get('depo_adi', '')).strip(),
                        'stok_grup': str(row.get('stok_grup', '')).strip(), 
                        'depo_sinif': str(row.get('depo_sinif', '')).strip(),
                        'malzeme_adi': str(row.get('malzeme_adi', 'BİLİNMEYEN')).strip(),
                        'barkod': str(row.get('barkod', '')).strip(),
                        'olcu_birimi': str(row.get('olcu_birimi', 'ADET')).strip(),
                        'renk': standardize_id_part(row.get('renk')),
                        
                        'seri_no': seri_no_val, 
                        
                        'sistem_stogu': sistem_stogu_val,
                        'sistem_tutari': sistem_tutari_val,
                        'birim_fiyat': birim_fiyat_val
                    }
                )
                success_count += 1

            except Exception as e:
                # Hata, hangi satırın hangi veriyi float'a çeviremediğini gösterir
                self.stderr.write(self.style.WARNING(f"Satır {index+2} yüklenemedi (Kodu: {row.get('malzeme_kodu', 'Bilinmiyor')}). Hata: {e}"))
                continue
        
        self.stdout.write(self.style.SUCCESS(f'Yükleme Tamamlandı: {success_count} adet benzersiz stok kaydı yüklendi/güncellendi.'))
