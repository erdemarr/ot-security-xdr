# OT Security XDR (MVP)

> Endüstriyel (OT) ağlar için hafif, açık kaynaklı bir **XDR / SIEM platformu prototipi**: ağ saldırı tespiti (NIDS), sunucu saldırı tespiti (HIDS), tehdit istihbaratı ve otomatik yanıt (SOAR) tek masaüstü uygulamasında; uzak ajanlardan olay toplayan merkezi bir SIEM ile birlikte.

> ⚠️ **Prototip uyarısı.** Bu proje eğitim amaçlı bir MVP'dir. SOAR modülü güvenlik duvarı kuralı **simüle eder** (gerçek kural eklemez), HIDS **simüle edilmiş** bir auth log'u okur, `central_siem/agent.py` ise **senaryolu demo olaylar** gönderir. Üretim ağlarında kullanmayın.

## Özellikler

- **NIDS:** Scapy ile canlı trafik analizi; hassas port (22, 23, 445, 3389) erişimi ve DoS benzeri yoğunluk tespiti.
- **Uyarlanabilir taban çizgisi:** İlk 10 sn'de IP başına normal paket hızını öğrenir, dinamik eşik belirler (ortalama + 3σ, en az 50 pkt/sn).
- **HIDS:** Linux `auth.log` benzeri dosyada başarısız SSH girişleri ve yetki yükseltme izleme.
- **CTI:** Dış IP'ler için ülke / ISP zenginleştirmesi.
- **SOAR (simüle):** Tehditleri kuyruktan alır, IP engelleme / hesap kilitleme aksiyonlarını tekrar etmeden üretir.
- **Panel:** PyQt6 koyu tema, canlı sayaçlar, renk kodlu log tablosu, filtreler, CSV adli rapor.
- **Merkezi SIEM:** Çok iş parçacıklı TCP sunucusu + SQLite, kendi canlı paneliyle.

Mimari diyagram ve ayrıntılı kurulum için [README.md](README.md) dosyasına bakın.

## Hızlı başlangıç

```bash
pip install -r requirements.txt
cd edge_sensor && sudo python main.py        # Windows: Yönetici + Npcap

# Merkezi SIEM demosu (3 ayrı terminal, aynı klasör):
cd central_siem
python server.py
python agent.py
python dashboard.py
```

## Yol haritası

Gerçek SOAR aksiyonları (dry-run ile), ajan-sunucu arasında kimlik doğrulama/TLS, gerçek auth.log desteği, Modbus/S7/DNP3 farkındalığı, modüler yapı ve birim testleri.

## Lisans

MIT
