from django import forms

class SayimGirisForm(forms.Form):
    # Stok Kodu standard kalır
    stok_kod = forms.CharField(label='1. Stok Kodu (ENTER)', max_length=100, required=False, widget=forms.TextInput(attrs={'autofocus': 'autofocus'}))
    
   # Parti No: Datalist kullanacağız, varsayılan değer atanmıyor
    parti_no = forms.CharField(label='2. Parti No (Seçim / Opsiyonel)', max_length=100, required=False, 
                                widget=forms.TextInput(attrs={'list': 'parti-datalist'}))

    # Renk: Datalist kullanacağız, varsayılan değer atanmıyor
    renk = forms.CharField(label='3. Renk / Varyant (Seçim / Opsiyonel)', max_length=100, required=False, 
                           widget=forms.TextInput(attrs={'list': 'renk-datalist'}))
                           
    miktar = forms.CharField(label='4. Sayım Miktarı', max_length=50)