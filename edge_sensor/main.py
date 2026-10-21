import sys
import sqlite3
import csv
import os
import time 
import requests 
import queue    
import random
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton, 
                             QVBoxLayout, QHBoxLayout, QWidget, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QLabel, QFrame,
                             QMessageBox)
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer

from scapy.all import sniff, IP, TCP, UDP

istihbarat_kuyrugu = queue.Queue()
soar_aksiyon_kuyrugu = queue.Queue() # YENİ: SOAR otonom yanıt kuyruğu

# 1. VERİTABANI KURULUMU
def veritabani_kur():
    baglanti = sqlite3.connect("ot_guvenlik.db")
    imlec = baglanti.cursor()
    imlec.execute('''
        CREATE TABLE IF NOT EXISTS guvenlik_loglari (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tarih_saat TEXT,
            olay_detayi TEXT,
            durum TEXT
        )
    ''')
    baglanti.commit()
    baglanti.close()

# 2. YENİ: SOAR (OTONOM YANIT VE ORKESTRASYON) MOTORU
class SOARMotoru(QThread):
    soar_sinyali = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.calisiyor = True
        self.engellenen_varliklar = set()

    def run(self):
        self.soar_sinyali.emit("SOAR AJANI AKTİF: Otonom müdahale motoru dinlemede...", "Sistem Aksiyonu")
        while self.calisiyor:
            try:
                # Tehdit kuyruğundan zararlı varlığı (IP veya Servis) al (0.5 saniye zaman aşımı)
                tehdit_kaynagi = soar_aksiyon_kuyrugu.get(timeout=0.5)
                
                if tehdit_kaynagi not in self.engellenen_varliklar:
                    self.engellenen_varliklar.add(tehdit_kaynagi)
                    
                    # OTONOM AKSİYON SİMÜLASYONU (Gerçek işletim sisteminde firewall kuralı ekleme simülasyonu)
                    # Windows'ta netsh veya Linux'te iptables komutlarının otonom tetiklendiği an
                    zaman_damgasi = datetime.now().strftime("%H:%M:%S")
                    
                    if "." in tehdit_kaynagi: # Eğer bir IP adresiyse
                        aksiyon_mesaji = f"SOAR OTONOM AKSİYON: {tehdit_kaynagi} IP adresi Firewall kuralı ile kalıcı olarak izole edildi."
                    else: # Linux HIDS'den gelen bir kullanıcı/servis adı ise
                        aksiyon_mesaji = f"SOAR OTONOM AKSİYON: Tehdit oluşturan '{tehdit_kaynagi}' hesabı kilitlendi ve oturumları sonlandırıldı."
                        
                    self.soar_sinyali.emit(aksiyon_mesaji, "SOAR Engelleme")
            except queue.Empty:
                continue

    def durdur(self):
        self.calisiyor = False

# 3. CTI (İSTİHBARAT) MOTORU
class CTIMotoru(QThread):
    cti_sinyali = pyqtSignal(str, str)
    def __init__(self):
        super().__init__()
        self.calisiyor = True
        self.sorgulanan_ipler = set()

    def run(self):
        while self.calisiyor:
            try:
                supheli_ip = istihbarat_kuyrugu.get(timeout=1)
                if supheli_ip not in self.sorgulanan_ipler:
                    self.sorgulanan_ipler.add(supheli_ip)
                    if not supheli_ip.startswith(("192.168.", "10.", "172.", "127.")):
                        try:
                            cevap = requests.get(f"http://ip-api.com/json/{supheli_ip}?fields=status,country,city,isp", timeout=3)
                            veri = cevap.json()
                            if veri.get("status") == "success":
                                ulke = veri.get("country", "Bilinmiyor")
                                cti_mesaji = f"CTI RAPORU: {supheli_ip} -> Ülke: {ulke} | ISP: {veri.get('isp', 'Bilinmiyor')}"
                                self.cti_sinyali.emit(cti_mesaji, "İstihbarat")
                        except: pass
            except queue.Empty: continue
    def durdur(self): self.calisiyor = False

# 4. YAPAY ZEKA VE AĞ MOTORU (NIDS)
class AgDinleyici(QThread):
    yeni_paket_sinyali = pyqtSignal(str, str) 
    def __init__(self):
        super().__init__()
        self.calisiyor = True
        self.ip_sayaclari = {} 
        self.son_sifirlama = time.time() 
        self.otomatik_kara_liste = set() 
        self.egitim_modu = True
        self.egitim_baslangici = time.time()
        self.dinamik_esik = 9999 

    def run(self):
        self.egitim_modu, self.egitim_baslangici, self.dinamik_esik = True, time.time(), 9999
        self.tarihce = []
        self.otomatik_kara_liste.clear()
        self.yeni_paket_sinyali.emit("YAPAY ZEKA DEVREDE: Ağ profili çıkarılıyor (10 Sn. Eğitim Modu)...", "Sistem Aksiyonu")
        while self.calisiyor:
            try: sniff(timeout=1, prn=self.paket_analiz, store=False)
            except Exception as e:
                self.yeni_paket_sinyali.emit(f"HATA: {str(e)}", "Kritik Tehdit")
                self.calisiyor = False

    def paket_analiz(self, paket):
        su_an = time.time()
        gecen_sure = su_an - self.egitim_baslangici
        
        if su_an - self.son_sifirlama > 1.0:
            if self.ip_sayaclari:
                if self.egitim_modu: self.tarihce.append(max(self.ip_sayaclari.values()))
            if self.egitim_modu and gecen_sure > 10.0:
                self.egitim_modu = False
                if self.tarihce:
                    ort = sum(self.tarihce) / len(self.tarihce)
                    std = (sum((x - ort) ** 2 for x in self.tarihce) / len(self.tarihce)) ** 0.5
                    self.dinamik_esik = max(int(ort + (3 * std)), 50)
                else: self.dinamik_esik = 100 
                self.yeni_paket_sinyali.emit(f"AI EĞİTİMİ BİTTİ: Yeni Dinamik DoS Eşiği: {self.dinamik_esik} pkt/sn", "Sistem Aksiyonu")
            self.ip_sayaclari.clear()
            self.son_sifirlama = su_an

        if IP in paket:
            kaynak_ip, hedef_ip = paket[IP].src, paket[IP].dst
            if kaynak_ip in self.otomatik_kara_liste: return
            self.ip_sayaclari[kaynak_ip] = self.ip_sayaclari.get(kaynak_ip, 0) + 1

            if not self.egitim_modu and self.ip_sayaclari[kaynak_ip] > self.dinamik_esik:
                self.otomatik_kara_liste.add(kaynak_ip)
                self.yeni_paket_sinyali.emit(f"AI ANOMALİ TESPİTİ: {kaynak_ip} eşiği aştı. Bloke edildi!", "DoS Engellendi")
                istihbarat_kuyrugu.put(kaynak_ip)
                soar_aksiyon_kuyrugu.put(kaynak_ip) # YENİ: SOAR motoruna otonom müdahale için IP'yi fırlat
                return 

            protokol, durum, port = "Bilinmiyor", "Güvenli", 0
            if TCP in paket: port, protokol = paket[TCP].dport, f"TCP (Port: {paket[TCP].dport})"
            elif UDP in paket: port, protokol = paket[UDP].dport, f"UDP (Port: {paket[UDP].dport})"
            
            detay = f"Trafik: {kaynak_ip}  >>>  {hedef_ip}  [{protokol}]"
            if port in [22, 23, 3389, 445]:
                durum, detay = "Kritik Tehdit", f"HASSAS PORT ERİŞİMİ (Port {port}): {kaynak_ip}"
                istihbarat_kuyrugu.put(kaynak_ip)
                soar_aksiyon_kuyrugu.put(kaynak_ip) # YENİ: Kritik port taramasını da SOAR'a bildir

            self.yeni_paket_sinyali.emit(detay, durum)
    def durdur(self): self.calisiyor = False

# 5. HIDS MOTORU
class HIDSMotoru(QThread):
    hids_sinyali = pyqtSignal(str, str)
    def __init__(self):
        super().__init__()
        self.calisiyor = True
        self.log_dosyasi = "simule_auth.log"

    def run(self):
        with open(self.log_dosyasi, "w") as f:
            f.write("Linux Syslog HIDS Simulation Started...\n")
        self.hids_sinyali.emit("HIDS AJANI BAŞLATILDI: auth.log dinleniyor...", "Sistem Aksiyonu")
        
        with open(self.log_dosyasi, "r") as f:
            f.seek(0, 2)
            while self.calisiyor:
                satir = f.readline()
                if not satir:
                    time.sleep(0.5)
                    self.sahte_log_uret()
                    continue
                
                satir = satir.strip()
                if "Failed password" in satir:
                    self.hids_sinyali.emit(f"HIDS ALARMI (SSH): {satir}", "Kritik HIDS")
                    # SOAR'a saldırgan IP'sini veya kullanıcıyı otomatik bildir
                    if "from " in satir:
                        parcalar = satir.split("from ")
                        if len(parcalar) > 1:
                            ip_kismi = parcalar[1].split(" ")[0]
                            soar_aksiyon_kuyrugu.put(ip_kismi)
                elif "COMMAND=/usr/bin/su" in satir or "sudo" in satir:
                    if "incorrect password" in satir:
                        self.hids_sinyali.emit(f"HIDS ALARMI (Yetki İhlali): {satir}", "Kritik HIDS")
                        soar_aksiyon_kuyrugu.put("root-kullanici-denemesi")
                    else:
                        self.hids_sinyali.emit(f"HIDS BİLGİ (Root Erişimi): {satir}", "HIDS Uyarısı")

    def sahte_log_uret(self):
        if random.random() < 0.15:
            senaryolar = [
                f"sshd[1024]: Failed password for root from 192.168.1.{random.randint(10,50)} port 42312 ssh2",
                f"sshd[2048]: Failed password for invalid user admin from 10.0.0.{random.randint(1,100)} port 53211 ssh2",
                f"sudo: pam_unix(sudo:auth): authentication failure; logname=analyst uid=1000 euid=0 tty=/dev/pts/1",
                f"sudo: analyst : TTY=pts/1 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/su"
            ]
            with open(self.log_dosyasi, "a") as f:
                f.write(random.choice(senaryolar) + "\n")

    def durdur(self): self.calisiyor = False


# 6. KULLANICI ARAYÜZÜ (v7.0 - SOAR Entegrasyonlu)
class AnaPencere(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OT Güvenlik Merkezi - v7.0 (SOAR Otonom Yanıt Platformu)")
        self.resize(1300, 780)
        self.setStyleSheet("background-color: #1e272e;")

        self.aktif_filtre = "HEPSİ"

        ana_layout = QVBoxLayout()
        dashboard_layout = QHBoxLayout()

        def kart_olustur(baslik, renk):
            frame = QFrame()
            frame.setStyleSheet(f"background-color: #2c3e50; border-top: 5px solid {renk}; border-radius: 5px;")
            frame_layout = QVBoxLayout()
            lbl_baslik = QLabel(baslik)
            lbl_baslik.setFont(QFont("Arial", 9, QFont.Weight.Bold))
            lbl_baslik.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_baslik.setStyleSheet("color: #bdc3c7; border: none;")
            lbl_deger = QLabel("0")
            lbl_deger.setFont(QFont("Arial", 22, QFont.Weight.Bold))
            lbl_deger.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_deger.setStyleSheet(f"color: {renk}; border: none;")
            frame_layout.addWidget(lbl_baslik)
            frame_layout.addWidget(lbl_deger)
            frame.setLayout(frame_layout)
            return frame, lbl_deger

        self.kart_toplam, self.lbl_toplam = kart_olustur("TOPLAM", "#3498db")
        self.kart_guvenli, self.lbl_guvenli = kart_olustur("GÜVENLİ", "#2ecc71") 
        self.kart_kritik, self.lbl_kritik = kart_olustur("AĞ TEHDİDİ", "#e74c3c")
        self.kart_hids, self.lbl_hids = kart_olustur("LINUX HIDS", "#00cec9")
        self.kart_soar, self.lbl_soar = kart_olustur("SOAR OTONOM", "#e84393") # YENİ: Pembe/Mor SOAR Kartı
        self.kart_istihbarat, self.lbl_istihbarat = kart_olustur("CTI", "#f1c40f") 

        dashboard_layout.addWidget(self.kart_toplam)
        dashboard_layout.addWidget(self.kart_guvenli)
        dashboard_layout.addWidget(self.kart_kritik)
        dashboard_layout.addWidget(self.kart_hids)
        dashboard_layout.addWidget(self.kart_soar)
        dashboard_layout.addWidget(self.kart_istihbarat)
        ana_layout.addLayout(dashboard_layout)

        # --- KONTROL BUTONLARI ---
        buton_layout = QHBoxLayout()
        self.btn_sensor = QPushButton("NIDS Başlat")
        self.btn_sensor.setStyleSheet("background-color: #2980b9; color: white; padding: 10px; font-weight: bold; border-radius: 5px;")
        self.btn_sensor.clicked.connect(self.sensor_tetikle)
        buton_layout.addWidget(self.btn_sensor)

        self.btn_hids = QPushButton("HIDS Başlat")
        self.btn_hids.setStyleSheet("background-color: #00cec9; color: black; padding: 10px; font-weight: bold; border-radius: 5px;")
        self.btn_hids.clicked.connect(self.hids_tetikle)
        buton_layout.addWidget(self.btn_hids)

        self.btn_soar = QPushButton("SOAR Otonom Yanıtı Başlat")
        self.btn_soar.setStyleSheet("background-color: #e84393; color: white; padding: 10px; font-weight: bold; border-radius: 5px;")
        self.btn_soar.clicked.connect(self.soar_tetikle)
        buton_layout.addWidget(self.btn_soar)
        
        self.btn_rapor = QPushButton("Rapor Al")
        self.btn_rapor.setStyleSheet("background-color: #16a085; color: white; padding: 10px; font-weight: bold; border-radius: 5px;")
        self.btn_rapor.clicked.connect(self.rapor_olustur)
        buton_layout.addWidget(self.btn_rapor)
        ana_layout.addLayout(buton_layout)

        # --- FİLTRELEME SEKME BUTONLARI ---
        filtre_layout = QHBoxLayout()
        
        def filtre_butonu_olustur(metin, filtre_kodu, renk):
            btn = QPushButton(metin)
            btn.setStyleSheet(f"background-color: #34495e; color: {renk}; border: 2px solid {renk}; padding: 8px; font-weight: bold; border-radius: 4px;")
            btn.clicked.connect(lambda: self.filtre_degistir(filtre_kodu))
            return btn

        self.btn_f_hepsi = filtre_butonu_olustur("Tüm Loglar", "HEPSİ", "#ffffff")
        self.btn_f_ag = filtre_butonu_olustur("Sadece Ağ (NIDS)", "AG", "#2ecc71")
        self.btn_f_hids = filtre_butonu_olustur("Sadece Linux (HIDS)", "HIDS", "#00cec9")
        self.btn_f_soar = filtre_butonu_olustur("Sadece SOAR Aksiyonları", "SOAR", "#e84393")
        self.btn_f_tehdit = filtre_butonu_olustur("Sadece Alarmlar", "TEHDIT", "#e74c3c")

        filtre_layout.addWidget(self.btn_f_hepsi)
        filtre_layout.addWidget(self.btn_f_ag)
        filtre_layout.addWidget(self.btn_f_hids)
        filtre_layout.addWidget(self.btn_f_soar)
        filtre_layout.addWidget(self.btn_f_tehdit)
        ana_layout.addLayout(filtre_layout)

        self.tablo = QTableWidget(0, 3) 
        self.tablo.setHorizontalHeaderLabels(["Tarih & Saat", "Olay Detayı", "Durum"])
        self.tablo.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tablo.setStyleSheet("background-color: #34495e; color: white; gridline-color: #2c3e50;")
        ana_layout.addWidget(self.tablo)

        konteyner = QWidget()
        konteyner.setLayout(ana_layout)
        self.setCentralWidget(konteyner)

        self.paket_havuzu = []
        self.guncelleme_zamanlayici = QTimer()
        self.guncelleme_zamanlayici.timeout.connect(self.havuzu_veritabanina_yaz)

        self.sensor_motoru = AgDinleyici()
        self.sensor_motoru.yeni_paket_sinyali.connect(self.havuza_ekle)

        self.istihbarat_motoru = CTIMotoru()
        self.istihbarat_motoru.cti_sinyali.connect(self.havuza_ekle)
        self.istihbarat_motoru.start()

        self.hids_motoru = HIDSMotoru()
        self.hids_motoru.hids_sinyali.connect(self.havuza_ekle)

        # YENİ: SOAR motorunu tanımla ve bağla
        self.soar_motoru = SOARMotoru()
        self.soar_motoru.soar_sinyali.connect(self.havuza_ekle)

        self.ekrani_guncelle()

    def filtre_degistir(self, kod):
        self.aktif_filtre = kod
        self.ekrani_guncelle()

    def sensor_tetikle(self):
        if not self.sensor_motoru.isRunning():
            self.sensor_motoru.calisiyor = True
            self.sensor_motoru.start() 
            self.guncelleme_zamanlayici.start(1000) 
            self.btn_sensor.setText("NIDS Aktif - Durdur")
            self.btn_sensor.setStyleSheet("background-color: #e74c3c; color: white; padding: 10px; font-weight: bold; border-radius: 5px;")
        else:
            self.sensor_motoru.durdur()
            self.sensor_motoru.wait()
            self.btn_sensor.setText("NIDS Başlat")
            self.btn_sensor.setStyleSheet("background-color: #2980b9; color: white; padding: 10px; font-weight: bold; border-radius: 5px;")

    def hids_tetikle(self):
        if not self.hids_motoru.isRunning():
            self.hids_motoru.calisiyor = True
            self.hids_motoru.start()
            self.guncelleme_zamanlayici.start(1000)
            self.btn_hids.setText("HIDS Aktif - Durdur")
            self.btn_hids.setStyleSheet("background-color: #e74c3c; color: white; padding: 10px; font-weight: bold; border-radius: 5px;")
        else:
            self.hids_motoru.durdur()
            self.hids_motoru.wait()
            self.btn_hids.setText("HIDS Başlat")
            self.btn_hids.setStyleSheet("background-color: #00cec9; color: black; padding: 10px; font-weight: bold; border-radius: 5px;")

    def soar_tetikle(self):
        if not self.soar_motoru.isRunning():
            self.soar_motoru.calisiyor = True
            self.soar_motoru.start()
            self.guncelleme_zamanlayici.start(1000)
            self.btn_soar.setText("SOAR Aktif - Durdur")
            self.btn_soar.setStyleSheet("background-color: #e74c3c; color: white; padding: 10px; font-weight: bold; border-radius: 5px;")
        else:
            self.soar_motoru.durdur()
            self.soar_motoru.wait()
            self.btn_soar.setText("SOAR Otonom Yanıtı Başlat")
            self.btn_soar.setStyleSheet("background-color: #e84393; color: white; padding: 10px; font-weight: bold; border-radius: 5px;")

    def havuza_ekle(self, detay, durum): self.paket_havuzu.append((detay, durum))

    def havuzu_veritabanina_yaz(self):
        if not self.paket_havuzu: return 
        su_an = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        kayitlar = [(su_an, p[0], p[1]) for p in self.paket_havuzu]
        baglanti = sqlite3.connect("ot_guvenlik.db")
        imlec = baglanti.cursor()
        imlec.executemany("INSERT INTO guvenlik_loglari (tarih_saat, olay_detayi, durum) VALUES (?, ?, ?)", kayitlar)
        baglanti.commit()
        baglanti.close()
        self.paket_havuzu.clear() 
        self.ekrani_guncelle() 
        
    def rapor_olustur(self):
        baglanti = sqlite3.connect("ot_guvenlik.db")
        imlec = baglanti.cursor()
        imlec.execute("SELECT * FROM guvenlik_loglari")
        veriler = imlec.fetchall()
        baglanti.close()
        if not veriler: return
        dosya_adi = f"Guvenlik_Raporu_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(dosya_adi, mode='w', newline='', encoding='utf-8-sig') as dosya:
            yazici = csv.writer(dosya, delimiter=';')
            yazici.writerow(["Kayıt No", "Tarih & Saat", "Olay Detayı", "Durum"])
            yazici.writerows(veriler)
        QMessageBox.information(self, "Rapor Hazır", f"Müşteri raporu oluşturuldu!\nKonum: {os.path.abspath(dosya_adi)}")

    def ekrani_guncelle(self):
        baglanti = sqlite3.connect("ot_guvenlik.db")
        imlec = baglanti.cursor()
        
        self.tablo.setRowCount(0) 
        
        if self.aktif_filtre == "AG":
            imlec.execute("SELECT tarih_saat, olay_detayi, durum FROM guvenlik_loglari WHERE durum IN ('Güvenli', 'Kritik Tehdit') ORDER BY id DESC LIMIT 100")
        elif self.aktif_filtre == "HIDS":
            imlec.execute("SELECT tarih_saat, olay_detayi, durum FROM guvenlik_loglari WHERE durum IN ('Kritik HIDS', 'HIDS Uyarısı') ORDER BY id DESC LIMIT 100")
        elif self.aktif_filtre == "SOAR":
            imlec.execute("SELECT tarih_saat, olay_detayi, durum FROM guvenlik_loglari WHERE durum = 'SOAR Engelleme' ORDER BY id DESC LIMIT 100")
        elif self.aktif_filtre == "TEHDIT":
            imlec.execute("SELECT tarih_saat, olay_detayi, durum FROM guvenlik_loglari WHERE durum IN ('Kritik Tehdit', 'Kritik HIDS', 'SOAR Engelleme') ORDER BY id DESC LIMIT 100")
        else:
            imlec.execute("SELECT tarih_saat, olay_detayi, durum FROM guvenlik_loglari ORDER BY id DESC LIMIT 100")
            
        satirlar = imlec.fetchall()
        
        for satir_no, satir_verisi in enumerate(satirlar):
            self.tablo.insertRow(satir_no)
            for sutun_no, sutun_verisi in enumerate(satir_verisi):
                hucre = QTableWidgetItem(str(sutun_verisi))
                durum_metni = satir_verisi[2]
                if durum_metni == "Kritik Tehdit": hucre.setBackground(QColor("#c0392b"))
                elif durum_metni == "Güvenli": hucre.setBackground(QColor("#27ae60"))
                elif durum_metni == "Sistem Aksiyonu": hucre.setBackground(QColor("#f39c12"))
                elif durum_metni == "İstihbarat": 
                    hucre.setBackground(QColor("#f1c40f"))
                    hucre.setForeground(QColor("black"))
                elif durum_metni == "Kritik HIDS":
                    hucre.setBackground(QColor("#0984e3"))
                    hucre.setForeground(QColor("white"))
                elif durum_metni == "HIDS Uyarısı":
                    hucre.setBackground(QColor("#74b9ff"))
                    hucre.setForeground(QColor("black"))
                elif durum_metni == "SOAR Engelleme":
                    hucre.setBackground(QColor("#e84393")) # Canlı Pembe/Mor (Otonom SOAR Rengi)
                    hucre.setForeground(QColor("white"))
                    
                self.tablo.setItem(satir_no, sutun_no, hucre)
        
        imlec.execute("SELECT durum, COUNT(*) FROM guvenlik_loglari GROUP BY durum")
        istatistikler = imlec.fetchall()
        
        toplam, guvenli, kritik, soar, cti, hids = 0, 0, 0, 0, 0, 0
        for durum, sayi in istatistikler:
            toplam += sayi
            if durum == "Güvenli": guvenli += sayi
            elif durum == "Kritik Tehdit": kritik += sayi
            elif durum == "SOAR Engelleme": soar += sayi
            elif durum == "İstihbarat": cti += sayi
            elif durum in ["Kritik HIDS", "HIDS Uyarısı"]: hids += sayi
                
        self.lbl_toplam.setText(str(toplam))
        self.lbl_guvenli.setText(str(guvenli))
        self.lbl_kritik.setText(str(kritik))
        self.lbl_hids.setText(str(hids))
        self.lbl_soar.setText(str(soar))
        self.lbl_istihbarat.setText(str(cti))
        
        baglanti.close()

if __name__ == "__main__":
    veritabani_kur()
    uygulama = QApplication(sys.argv)
    pencere = AnaPencere()
    pencere.show()
    sys.exit(uygulama.exec())