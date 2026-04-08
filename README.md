# MiniSOC-Analyzer

MiniSOC-Analyzer, gerçek zamanlı log analizi ve güvenlik alert üretimi için geliştirilmiş bir mini SOC (Security Operations Center) projesidir. Bu proje sayesinde farklı log kaynakları (auth, web, network) analiz edilerek olası güvenlik tehditleri tespit edilebilir ve raporlanabilir.

---

## Özellikler

- Auth, Web ve Network loglarının analizi  
- Brute Force, SQL Injection, XSS ve Port Scan tespiti  
- LOW / MEDIUM / HIGH risk seviyelerine göre uyarılar  
- MITRE ATT&CK mapping ile her alertin taktiği ve tekniği  
- Renkli terminal çıktısı (HIGH = kırmızı, MEDIUM = sarı, LOW = yeşil)  
- Raporlama:  
  - `report.txt`  
  - `report.csv`  
  - `report.xlsx`  

---

## Dosya Yapısı

MiniSOC-Analyzer/
│
├── analyzer.py # Ana analiz ve alert üretim scripti

├── logs/ # Örnek log dosyaları (auth.log, web.log, network.log)

├── report.txt # Terminal çıktısının kaydı

├── report.csv # CSV rapor

├── report.xlsx # Excel rapor

└── README.md


---

## Kullanım

1. Python ortamını kurun ve gerekli kütüphaneleri yükleyin:

```bash
pip install pandas colorama openpyxl
```

2. Log dosyalarını logs/ klasörüne yerleştirin
3. analyzer.py dosyasını çalıştırın:

```bash
python analyzer.py
```

4. Terminalde renkli alertleri görebilir, report.txt, report.csv ve report.xlsx dosyalarından detaylı rapor alabilirsiniz.

## Örnek Alertler

- [HIGH] Brute Force – Multiple failed login attempts detected

- [HIGH] SQL Injection – Possible SQL injection attempt

- [MEDIUM] XSS Attack – Cross-site scripting attempt detected

- [MEDIUM] Port Scan – Multiple ports accessed in short time

- [LOW] Suspicious Ping – Suspicious ping detected, low risk

## Teknolojiler

- Python 3.x

- Pandas (CSV/Excel export)

- Colorama (renkli terminal çıktısı)
