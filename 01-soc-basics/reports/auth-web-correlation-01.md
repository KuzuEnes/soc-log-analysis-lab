# Auth + Web Correlation Analysis 01

## Amaç

Bu çalışmada `auth.log` ve `access.log` birlikte analiz edilmiştir.

Amaç, aynı IP adresinin hem SSH authentication tarafında hem de web access loglarında şüpheli davranış gösterip göstermediğini tespit etmektir.

## Log Kaynakları

- `01-soc-basics/data/auth.log`
- `01-soc-basics/data/access.log`

## Korelasyon Mantığı

Tek bir log kaynağı bazen yeterli olmayabilir.

Örneğin:

- Birkaç başarısız SSH login denemesi kullanıcı hatası olabilir.
- Birkaç web 404 hatası bot trafiği olabilir.
- `/admin` veya `/.git/config` istekleri otomatik tarama olabilir.

Ancak aynı IP adresi hem SSH login denemesi yapıyor hem de web tarafında şüpheli pathler deniyorsa olayın riski artar.

## Tespit Edilen IP

```text
203.0.113.55
```

## Auth Log Bulguları

`203.0.113.55` IP adresinden SSH tarafında başarısız giriş denemeleri görülmüştür:

```text
Failed password for admin
Failed password for root
Failed password for test
```

Bu davranış credential access veya servis keşfi denemesi olabilir.

## Web Access Log Bulguları

Aynı IP adresi web tarafında şu pathleri denemiştir:

```text
/admin
/wp-login.php
/.git/config
/backup.zip
/phpinfo.php
/config.php
```

Bu davranış web path scan veya directory enumeration olarak değerlendirilebilir.

## Risk Skoru

Bu çalışmada basit bir risk skoru kullanılmıştır:

```text
3+ failed SSH login      → +30
5+ HTTP 404 response     → +20
3+ suspicious web paths  → +20
```

Bu nedenle `203.0.113.55` için risk seviyesi:

```text
HIGH
```

## MITRE ATT&CK Mapping

### Active Scanning

- Technique: Active Scanning
- Technique ID: T1595
- Tactic: Reconnaissance

### Brute Force

- Technique: Brute Force
- Technique ID: T1110
- Tactic: Credential Access

### Exploit Public-Facing Application

- Technique: Exploit Public-Facing Application
- Technique ID: T1190
- Tactic: Initial Access

## False Positive İhtimalleri

Bu olay yine de kesin saldırı kanıtı değildir.

Olası false positive nedenleri:

- Güvenlik ekibi test yapıyor olabilir.
- Otomatik vulnerability scanner çalışmış olabilir.
- İnternetteki genel bot trafiği olabilir.
- IP bir NAT/proxy arkasından geliyor olabilir.

## SOC Analyst Olarak Sonraki Adımlar

1. Kaynak IP adresi iç ağ mı dış ağ mı kontrol edilir.
2. Firewall veya WAF loglarında aynı IP aranır.
3. Bu IP’den başka sunuculara bağlantı var mı kontrol edilir.
4. Web isteklerinden sonra 200 veya 500 gibi dikkat çekici cevaplar var mı incelenir.
5. SSH tarafında başarısız denemelerden sonra başarılı login var mı kontrol edilir.
6. Gerekirse IP blocklist’e alınır.
7. Eğer iç ağ IP’si ise host üzerinde EDR incelemesi yapılır.

## Sonuç

Bu analizde aynı IP adresinin birden fazla log kaynağında şüpheli davranış gösterdiği tespit edilmiştir.

Bu, basit log analizinden bir üst seviye olan korelasyon analizine geçiştir.

SOC analyst için önemli nokta, tek bir alarmı izole değerlendirmek yerine farklı log kaynaklarını birleştirerek olayın gerçek riskini anlamaktır.
