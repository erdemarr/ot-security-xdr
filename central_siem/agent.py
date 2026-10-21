import socket
import json
import time
from datetime import datetime

class GuvenlikAjani:
    def __init__(self, sunucu_ip='127.0.0.1', sunucu_port=9999, ajans_adi="Fabrika-Saha-Agent-01"):
        self.sunucu_ip = sunucu_ip
        self.sunucu_port = sunucu_port
        self.ajans_adi = ajans_adi

    def veri_gonder(self, detay, durum):
        try:
            soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soket.connect((self.sunucu_ip, self.sunucu_port))
            
            log_paketi = {
                "ajans_adi": self.ajans_adi,
                "tarih": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "detay": detay,
                "durum": durum
            }
            
            soket.sendall(json.dumps(log_paketi).encode('utf-8'))
            soket.close()
        except Exception as e:
            print(f"[-] Merkeze veri gönderilemedi (Sunucu kapalı olabilir): {e}")

    def calistir(self):
        print(f"[+] {self.ajans_adi} Ajanı Devrede. Merkeze bağlanılıyor...")
        
        # Test amaçlı periyodik olarak merkeze güvenlik olayları fırlatalım
        senaryolar = [
            ("Trafik: 192.168.1.50 >>> 192.168.1.1 [TCP (Port: 80)]", "Güvenli"),
            ("HASSAS PORT ERİŞİMİ (Port 22): 185.220.101.5", "Kritik Tehdit"),
            ("SOAR OTONOM AKSİYON: 185.220.101.5 IP adresi Firewall ile izole edildi.", "SOAR Engelleme")
        ]

        while True:
            for detay, durum in senaryolar:
                print(f"[>] Merkeze raporlanıyor: {detay}")
                self.veri_gonder(detay, durum)
                time.sleep(3) # Her 3 saniyede bir merkeze olay bildir

if __name__ == "__main__":
    ajan = GuvenlikAjani()
    ajan.calistir()