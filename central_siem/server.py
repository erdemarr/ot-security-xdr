import socket
import threading
import json
import sqlite3
from datetime import datetime

# Merkezi Sunucu Veritabanı Kurulumu
def sunucu_veritabani_kur():
    baglanti = sqlite3.connect("merkezi_siem.db")
    imlec = baglanti.cursor()
    imlec.execute('''
        CREATE TABLE IF NOT EXISTS merkezi_loglar (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ajans_adi TEXT,
            tarih_saat TEXT,
            olay_detayi TEXT,
            durum TEXT
        )
    ''')
    baglanti.commit()
    baglanti.close()

class MerkezSunucu:
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.calisiyor = True

    def baslat(self):
        sunucu_veritabani_kur()
        self.soket.bind((self.host, self.port))
        self.soket.listen(5)
        print(f"[+] MERKEZİ XDR SUNUCUSU BAŞLATILDI: {self.host}:{self.port} üzerinden ajanlar bekleniyor...")

        while self.calisiyor:
            try:
                istemci_soket, adres = self.soket.accept()
                # Her bağlanan ajan için ayrı bir iş parçacığı (Thread) aç
                istihbarat_ipligi = threading.Thread(target=self.ajan_yoneticisi, args=(istemci_soket, adres))
                istihbarat_ipligi.daemon = True
                istihbarat_ipligi.start()
            except Exception as e:
                print(f"[-] Sunucu Dinleme Hatası: {e}")
                break

    def ajan_yoneticisi(self, soket, adres):
        print(f"[+] Yeni Ajan Bağlandı: {adres}")
        try:
            while True:
                veri = soket.recv(4096)
                if not veri:
                    break
                
                # Ajanlardan gelen JSON verisini çözer
                mesaj_str = veri.decode('utf-8')
                log_paketi = json.loads(mesaj_str)
                
                ajans_adi = log_paketi.get("ajans_adi", "Bilinmeyen-Ajan")
                tarih = log_paketi.get("tarih", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                detay = log_paketi.get("detay", "Veri yok")
                durum = log_paketi.get("durum", "Güvenli")

                # Merkezi veritabanına kaydet
                self.veritabanina_yaz(ajans_adi, tarih, detay, durum)
                print(f"[{ajans_adi}] ({durum}): {detay}")

        except json.JSONDecodeError:
            print(f"[-] Hatalı veri formatı alındı: {adres}")
        except Exception as e:
            print(f"[-] Ajan Bağlantı Hatası ({adres}): {e}")
        finally:
            soket.close()
            print(f"[-] Ajan Bağlantısı Koptu: {adres}")

    def veritabanina_yaz(self, ajans_adi, tarih, detay, durum):
        baglanti = sqlite3.connect("merkezi_siem.db")
        imlec = baglanti.cursor()
        imlec.execute("INSERT INTO merkezi_loglar (ajans_adi, tarih_saat, olay_detayi, durum) VALUES (?, ?, ?, ?)",
                      (ajans_adi, tarih, detay, durum))
        baglanti.commit()
        baglanti.close()

if __name__ == "__main__":
    sunucu = MerkezSunucu()
    sunucu.baslat()