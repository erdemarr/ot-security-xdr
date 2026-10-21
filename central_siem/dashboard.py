import sys
import sqlite3
import os
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton, 
                             QVBoxLayout, QHBoxLayout, QWidget, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QLabel, QFrame,
                             QMessageBox)
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtCore import QTimer, Qt

class MerkezSIEMPanceresi(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OT Security - Merkezi Komuta Kontrol ve SIEM Paneli (Enterprise)")
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

        self.kart_toplam, self.lbl_toplam = kart_olustur("TOPLAM MERKEZİ LOG", "#3498db")
        self.kart_guvenli, self.lbl_guvenli = kart_olustur("GÜVENLİ TRAFİK", "#2ecc71") 
        self.kart_kritik, self.lbl_kritik = kart_olustur("KRİTİK TEHDİT", "#e74c3c")
        self.kart_soar, self.lbl_soar = kart_olustur("SOAR OTONOM", "#e84393")
        self.kart_istihbarat, self.lbl_istihbarat = kart_olustur("CTI / DİĞER", "#f1c40f") 

        dashboard_layout.addWidget(self.kart_toplam)
        dashboard_layout.addWidget(self.kart_guvenli)
        dashboard_layout.addWidget(self.kart_kritik)
        dashboard_layout.addWidget(self.kart_soar)
        dashboard_layout.addWidget(self.kart_istihbarat)
        ana_layout.addLayout(dashboard_layout)

        # --- ÜST KONTROL BUTONLARI ---
        buton_layout = QHBoxLayout()
        self.btn_yenile = QPushButton("Veritabanını Yenile (Sync)")
        self.btn_yenile.setStyleSheet("background-color: #2980b9; color: white; padding: 10px; font-weight: bold; border-radius: 5px;")
        self.btn_yenile.clicked.connect(self.ekrani_guncelle)
        buton_layout.addWidget(self.btn_yenile)

        self.btn_rapor = QPushButton("Merkezi Adli Rapor Al (CSV)")
        self.btn_rapor.setStyleSheet("background-color: #16a085; color: white; padding: 10px; font-weight: bold; border-radius: 5px;")
        self.btn_rapor.clicked.connect(self.rapor_olustur)
        buton_layout.addWidget(self.btn_rapor)
        ana_layout.addLayout(buton_layout)

        # --- FİLTRELEME SEKMELERİ ---
        filtre_layout = QHBoxLayout()
        
        def filtre_butonu_olustur(metin, filtre_kodu, renk):
            btn = QPushButton(metin)
            btn.setStyleSheet(f"background-color: #34495e; color: {renk}; border: 2px solid {renk}; padding: 8px; font-weight: bold; border-radius: 4px;")
            btn.clicked.connect(lambda: self.filtre_degistir(filtre_kodu))
            return btn

        self.btn_f_hepsi = filtre_butonu_olustur("Tüm Ajan Logları", "HEPSİ", "#ffffff")
        self.btn_f_ag = filtre_butonu_olustur("Güvenli Trafik", "GUVENLI", "#2ecc71")
        self.btn_f_kritik = filtre_butonu_olustur("Kritik Tehditler", "KRITIK", "#e74c3c")
        self.btn_f_soar = filtre_butonu_olustur("SOAR Aksiyonları", "SOAR", "#e84393")

        filtre_layout.addWidget(self.btn_f_hepsi)
        filtre_layout.addWidget(self.btn_f_ag)
        filtre_layout.addWidget(self.btn_f_kritik)
        filtre_layout.addWidget(self.btn_f_soar)
        ana_layout.addLayout(filtre_layout)

        # --- MERKEZİ LOG TABLOSU (Ajan Adı sütunu eklendi) ---
        self.tablo = QTableWidget(0, 4) 
        self.tablo.setHorizontalHeaderLabels(["Ajan Adı", "Tarih & Saat", "Olay Detayı", "Durum"])
        self.tablo.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tablo.setStyleSheet("background-color: #34495e; color: white; gridline-color: #2c3e50;")
        ana_layout.addWidget(self.tablo)

        konteyner = QWidget()
        konteyner.setLayout(ana_layout)
        self.setCentralWidget(konteyner)

        # Otomatik senkronizasyon zamanlayıcısı (Her 2 saniyede bir merkezi DB'yi okur)
        self.timer = QTimer()
        self.timer.timeout.connect(self.ekrani_guncelle)
        self.timer.start(2000)

        self.ekrani_guncelle()

    def filtre_degistir(self, kod):
        self.aktif_filtre = kod
        self.ekrani_guncelle()

    def veritabani_kontrol(self):
        if not os.path.exists("merkezi_siem.db"):
            return False
        return True

    def ekrani_guncelle(self):
        if not self.veritabani_kontrol():
            return

        baglanti = sqlite3.connect("merkezi_siem.db")
        imlec = baglanti.cursor()
        
        self.tablo.setRowCount(0) 
        
        # Filtreleme mantığı
        if self.aktif_filtre == "GUVENLI":
            imlec.execute("SELECT ajans_adi, tarih_saat, olay_detayi, durum FROM merkezi_loglar WHERE durum = 'Güvenli' ORDER BY id DESC LIMIT 100")
        elif self.aktif_filtre == "KRITIK":
            imlec.execute("SELECT ajans_adi, tarih_saat, olay_detayi, durum FROM merkezi_loglar WHERE durum = 'Kritik Tehdit' ORDER BY id DESC LIMIT 100")
        elif self.aktif_filtre == "SOAR":
            imlec.execute("SELECT ajans_adi, tarih_saat, olay_detayi, durum FROM merkezi_loglar WHERE durum = 'SOAR Engelleme' ORDER BY id DESC LIMIT 100")
        else:
            imlec.execute("SELECT ajans_adi, tarih_saat, olay_detayi, durum FROM merkezi_loglar ORDER BY id DESC LIMIT 100")
            
        satirlar = imlec.fetchall()
        
        for satir_no, satir_verisi in enumerate(satirlar):
            self.tablo.insertRow(satir_no)
            for sutun_no, sutun_verisi in enumerate(satir_verisi):
                hucre = QTableWidgetItem(str(sutun_verisi))
                durum_metni = satir_verisi[3] # Durum kolon pozisyonu
                
                if durum_metni == "Kritik Tehdit": 
                    hucre.setBackground(QColor("#c0392b"))
                elif durum_metni == "Güvenli": 
                    hucre.setBackground(QColor("#27ae60"))
                elif durum_metni == "SOAR Engelleme": 
                    hucre.setBackground(QColor("#e84393"))
                    hucre.setForeground(QColor("white"))
                else:
                    hucre.setBackground(QColor("#34495e"))
                    
                self.tablo.setItem(satir_no, sutun_no, hucre)
        
        # Dashboard sayaçlarını güncelle
        imlec.execute("SELECT durum, COUNT(*) FROM merkezi_loglar GROUP BY durum")
        istatistikler = imlec.fetchall()
        
        toplam, guvenli, kritik, soar, diger = 0, 0, 0, 0, 0
        for durum, sayi in istatistikler:
            toplam += sayi
            if durum == "Güvenli": guvenli += sayi
            elif durum == "Kritik Tehdit": kritik += sayi
            elif durum == "SOAR Engelleme": soar += sayi
            else: diger += sayi
                
        self.lbl_toplam.setText(str(toplam))
        self.lbl_guvenli.setText(str(guvenli))
        self.lbl_kritik.setText(str(kritik))
        self.lbl_soar.setText(str(soar))
        self.lbl_istihbarat.setText(str(diger))
        
        baglanti.close()

    def rapor_olustur(self):
        if not self.veritabani_kontrol():
            return
        baglanti = sqlite3.connect("merkezi_siem.db")
        imlec = baglanti.cursor()
        imlec.execute("SELECT * FROM merkezi_loglar")
        veriler = imlec.fetchall()
        baglanti.close()
        if not veriler: 
            return

        import csv
        dosya_adi = f"Merkezi_SIEM_Raporu_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(dosya_adi, mode='w', newline='', encoding='utf-8-sig') as dosya:
            yazici = csv.writer(dosya, delimiter=';')
            yazici.writerow(["Kayıt No", "Ajan Adı", "Tarih & Saat", "Olay Detayı", "Durum"])
            yazici.writerows(veriler)

        QMessageBox.information(self, "Rapor Hazır", f"Merkezi SIEM raporu oluşturuldu!\nKonum: {os.path.abspath(dosya_adi)}")

if __name__ == "__main__":
    uygulama = QApplication(sys.argv)
    pencere = MerkezSIEMPanceresi()
    pencere.show()
    sys.exit(uygulama.exec())