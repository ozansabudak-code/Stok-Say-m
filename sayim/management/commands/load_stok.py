import pandas as pd
from django.core.management.base import BaseCommand, CommandError
# Modelinizi ve merkezi fonksiyonlarınızı import edin
from sayim.models import Malzeme, standardize_id_part, generate_unique_id

class Command(BaseCommand):
    help = 'Belirtilen Excel dosyasından stok verilerini Malzemeler tablosuna yükler.'

    def add_arguments(self, parser):
        # Komut çalıştırılırken dosya yolunu girmeyi zorunlu kılar
        parser.add_argument('file_path', type=str, help='Yüklenecek Excel veya CSV dosyasının yolu')

    def handle(self, *args, **options):
        file_path = options['file_path']
        self.stdout.write(f"Dosya yolu: {file_path}")

        try:
            if file_path.lower().endswith(('.xlsx', '.xls')):
                df = pd.read_excel(file_path, header=0, sheet_name=0, na_filter=False, keep_default_na=True)
            elif file_path.lower().endswith('.csv'):
                # CSV yüklerken encoding sorununu ISO-8859-9 ile çözmeyi dener
                df = pd.read_csv(file_path, header=0, encoding='iso-8859-9', na_filter=False, keep_default_na=True)
            else:
                # CommandError, komut satırında kırmızı hata mesajı döndürür
                raise CommandError("Desteklenmeyen dosya formatı. Lütfen .xlsx, .xls veya .csv kullanın.")
        
        except FileNotFoundError:
            raise CommandError(f"HATA: Dosya bulunamadı: {file_path}")
        except Exception as e:
            raise CommandError(f"Dosya okunurken problem oluştu: {e}")

        # Sütun Eşleme: Orijinal kodunuzdaki 13 sütunluk yapıya uygun
        try:
            # Sütunları isimleriyle eşlemek yerine doğrudan indeksten alıyoruz
            df_selected = pd.DataFrame({
                'parti_no': df.iloc[:, 0],
                'lokasyon_kodu': df.iloc[:, 1],
                'depo_adi': df.iloc[:, 2],
                'malzeme_kodu': df.iloc[:, 3],
                'malzeme_adi': df.iloc[:, 4],
                'renk': df.iloc[:, 5], 
                'sistem_stogu': df.iloc[:, 6],
                'sistem_tutari': df.iloc[:, 7],
                'birim_fiyat': df.iloc[:, 8],
                'olcu_birimi': df.iloc[:, 9],
                'stok_grup': df.iloc[:, 10],
                'depo_sinif': df.iloc[:, 11],
                'barkod': df.iloc[:, 12]
            })
        except IndexError:
            raise CommandError("Excel sütun sayısı eşleşmiyor! Dosyanızın 13 sütun içerdiğinden emin olun (0'dan 12'ye).")


        # Veriyi Django modeline yükleme (update_or_create kullanarak)
        success_count = 0
        
        for index, row in df_selected.iterrows():
            try:
                malzeme_kodu_clean = standardize_id_part(row.get('malzeme_kodu'))
                
                if malzeme_kodu_clean == 'YOK':
                    continue 

                # 1. Benzersiz ID'yi hesapla
                benzersiz_id_val = generate_unique_id(
                    malzeme_kodu_clean,
                    standardize_id_part(row.get('parti_no')),
                    standardize_id_part(row.get('lokasyon_kodu', 'MERKEZ')),
                    standardize_id_part(row.get('renk'))
                )
                
                # 2. Kaydı bul ya da oluştur
                Malzeme.objects.update_or_create(
                    # Eşleşme kriteri (Benzersiz ID eşleşirse güncelle)
                    benzersiz_id=benzersiz_id_val,
                    defaults={
                        # Güncellenecek veya oluşturulacak değerler
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
                        'sistem_stogu': float(row.get('sistem_stogu', 0.0)),
                        'sistem_tutari': float(row.get('sistem_tutari', 0.0)),
                        'birim_fiyat': float(row.get('birim_fiyat', 0.0))
                    }
                )
                success_count += 1

            except Exception as e:
                self.stderr.write(self.style.WARNING(f"Satır {index+2} yüklenemedi (Kodu: {row.get('malzeme_kodu', 'Bilinmiyor')}). Hata: {e}"))
                continue
        
        self.stdout.write(self.style.SUCCESS(f'Yükleme Tamamlandı: {success_count} adet benzersiz stok kaydı yüklendi/güncellendi.'))