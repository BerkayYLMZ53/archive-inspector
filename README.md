# Archive Inspector

Bir ZIP dosyasının listesini, boyutlarını ve çıkarma sırasında sorun çıkarabilecek kayıtlarını gösterir. Dosyaları diske çıkarmadan indirilen arşivin içeriğine bakabilir, isteğe bağlı CRC denetimi çalıştırabilirsin.

## Kullanım

Python 3.12 veya üzeri yeterli. Komutları depo kökünde çalıştır.

```powershell
python inspect_archive.py ./arsiv.zip --list
python inspect_archive.py ./arsiv.zip --verify --max-mib 128
python inspect_archive.py ./arsiv.zip --json
```

Araç `../` ve mutlak yolları, Windows aygıt adlarını, ad çakışmalarını, sembolik bağlantıları, şifreli kayıtları ve belirgin sıkıştırma oranlarını işaretler. Yüksek oran bulgusu en az 1 MiB açılan ve en az 100 kat sıkıştırılmış kayıtlar için geçerlidir. Varsayılan inceleme yalnızca ZIP dizin bilgilerini okur. `--verify`, dosyaları parça parça okuyarak CRC bütünlüğünü denetler ve varsayılan olarak 256 MiB açık boyutla sınırlıdır.

Çıkış kodu `0` bulgu olmadığını, `1` bulgu bulunduğunu veya istenen CRC denetiminin atlandığını, `2` okuma ya da bütünlük hatasını gösterir. İç içe arşivler tek dosya olarak listelenir. Zararlı yazılım incelemesi için ayrı bir tarama gerekir.

## Testler

```powershell
python -m unittest discover -v
```
