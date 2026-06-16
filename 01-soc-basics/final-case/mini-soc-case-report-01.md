# Mini SOC Case Report 01

## SSH Brute Force, Password Spraying and Web Recon Activity

## 1. Executive Summary

Bu çalışmada sentetik Linux SSH authentication logları ve web access logları analiz edilmiştir.

Analiz sonucunda aşağıdaki şüpheli davranışlar tespit edilmiştir:

* Aynı IP adresinden çok sayıda başarısız SSH login denemesi
* Farklı kullanıcılara yönelik başarısız login denemeleri
* Başarısız giriş denemelerinden sonra başarılı login
* Web tarafında `/admin`, `/wp-login.php`, `/.git/config`, `/backup.zip` gibi şüpheli path denemeleri
* SQL injection markerları
* XSS markerları
* Aynı IP adresinin hem SSH hem web tarafında şüpheli aktivite göstermesi

Bu bulgular tek başına kesin saldırı kanıtı değildir; ancak SOC analisti tarafından öncelikli incelenmesi gereken şüpheli davranışlardır.

---

## 2. Scope

Bu analizde aşağıdaki log kaynakları incelenmiştir:

```text
01-soc-basics/data/auth.log
01-soc-basics/data/access.log
```

Kullanılan analiz scriptleri:

```text
01-soc-basics/scripts/analyze_auth_log.py
01-soc-basics/scripts/analyze_auth_log_v2.py
01-soc-basics/scripts/analyze_access_log.py
01-soc-basics/scripts/correlate_auth_web.py
```

---

## 3. Log Sources

### 3.1 Linux SSH Auth Log

SSH authentication logları başarılı ve başarısız login denemelerini incelemek için kullanılmıştır.

Örnek log satırı:

```text
Failed password for admin from 192.168.1.50
```

Bu satır, `192.168.1.50` IP adresinden `admin` kullanıcısına başarısız bir SSH giriş denemesi yapıldığını gösterir.

### 3.2 Web Access Log

Web access logları HTTP isteklerini, status code değerlerini ve istenen pathleri incelemek için kullanılmıştır.

Örnek log satırı:

```text
203.0.113.55 - - [16/Jun/2026:22:11:01 +0300] "GET /admin HTTP/1.1" 404 512
```

Bu satır, `203.0.113.55` IP adresinin `/admin` pathine istek gönderdiğini ve sunucudan `404` cevabı aldığını gösterir.

---

## 4. Key Findings

## Finding 1: Possible SSH Brute Force

`192.168.1.50` IP adresinden `admin` kullanıcısına kısa sürede 6 başarısız SSH login denemesi yapılmıştır.

Bu davranış brute force saldırısına işaret edebilir.

### Evidence

```text
192.168.1.50 -> admin -> 6 failed login attempts
```

### Risk

Orta seviye risklidir. Eğer bu denemelerden sonra başarılı login gerçekleşirse risk seviyesi yükselir.

---

## Finding 2: Possible Password Spraying

`203.0.113.8` IP adresinden farklı kullanıcı adlarına başarısız login denemeleri yapılmıştır.

Deneme yapılan kullanıcılar:

```text
ali
veli
ayse
mehmet
```

Bu davranış password spraying olabilir.

### Brute Force vs Password Spraying

```text
Brute force:
Bir kullanıcıya çok sayıda şifre denenir.

Password spraying:
Birden fazla kullanıcıya az sayıda ortak şifre denenir.
```

---

## Finding 3: Failed Login Followed by Successful Login

`172.16.10.20` IP adresinden `enes` kullanıcısı için önce 3 başarısız login denemesi, ardından başarılı login görülmüştür.

Bu bulgu diğerlerine göre daha kritiktir.

### Evidence

```text
172.16.10.20 -> enes -> 3 failed attempts
172.16.10.20 -> enes -> successful login
```

### Risk

Bu davranış credential compromise ihtimalini düşündürür.

Başarısız denemelerden sonra başarılı giriş görülmesi, saldırganın doğru şifreyi bulmuş veya geçerli credential elde etmiş olabileceğini gösterebilir.

---

## Finding 4: Web Path Scan / Directory Enumeration

`203.0.113.55` IP adresi web tarafında birçok şüpheli path denemiştir.

Denemeler:

```text
/admin
/wp-login.php
/.git/config
/backup.zip
/phpinfo.php
/config.php
```

Aynı IP adresi 6 adet HTTP 404 cevabı üretmiştir.

### Risk

Bu davranış saldırganın açık bırakılmış yönetim paneli, yedek dosya, config dosyası veya Git klasörü aradığını gösterebilir.

---

## Finding 5: SQL Injection Markers

`198.51.100.23` IP adresinden SQL injection markerları içeren istekler görülmüştür.

Örnek istekler:

```text
/search?q=%27%20OR%201%3D1--
/product?id=1%20UNION%20SELECT%201,2,3
```

URL decode edildiğinde dikkat çeken markerlar:

```text
' OR 1=1--
UNION SELECT
```

Bu davranış SQL injection denemesi olabilir.

---

## Finding 6: XSS Markers

`198.51.100.30` IP adresinden XSS markerları içeren istekler görülmüştür.

Örnek istekler:

```text
/comment?text=%3Cscript%3Ealert(1)%3C/script%3E
/profile?name=%3Cimg%20src=x%20onerror=alert(1)%3E
```

URL decode edildiğinde dikkat çeken markerlar:

```text
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

Bu davranış XSS denemesi olabilir.

---

## Finding 7: Auth + Web Correlation

`203.0.113.55` IP adresi hem SSH authentication loglarında hem de web access loglarında şüpheli davranış göstermiştir.

### Auth Bulguları

```text
Failed password for admin
Failed password for root
Failed password for test
```

### Web Bulguları

```text
/admin
/wp-login.php
/.git/config
/backup.zip
/phpinfo.php
/config.php
```

### Risk Yorumu

Aynı IP adresinin hem SSH login denemeleri yapması hem de web uygulamasında şüpheli pathleri taraması olayın önceliğini artırır.

Tek başına birkaç başarısız SSH login kullanıcı hatası olabilir.
Tek başına birkaç 404 cevabı bot trafiği olabilir.
Ancak ikisi aynı IP üzerinde birleştiğinde bu davranış daha şüpheli hale gelir.

---

## 5. MITRE ATT&CK Mapping

| Finding                         | Technique                         | Technique ID | Tactic                                                                |
| ------------------------------- | --------------------------------- | ------------ | --------------------------------------------------------------------- |
| SSH brute force                 | Brute Force                       | T1110        | Credential Access                                                     |
| Password spraying               | Brute Force: Password Spraying    | T1110.003    | Credential Access                                                     |
| Successful login after failures | Valid Accounts                    | T1078        | Initial Access / Persistence / Privilege Escalation / Defense Evasion |
| Web path scan                   | Active Scanning                   | T1595        | Reconnaissance                                                        |
| Web exploit attempts            | Exploit Public-Facing Application | T1190        | Initial Access                                                        |

---

## 6. Severity Assessment

| IP Address    | Observed Behavior                                | Severity |
| ------------- | ------------------------------------------------ | -------- |
| 192.168.1.50  | Multiple failed SSH login attempts against admin | Medium   |
| 203.0.113.8   | Multiple usernames targeted                      | Medium   |
| 172.16.10.20  | Failed logins followed by successful login       | High     |
| 203.0.113.55  | SSH failures + suspicious web path scan          | High     |
| 198.51.100.23 | SQL injection markers                            | Medium   |
| 198.51.100.30 | XSS markers                                      | Medium   |

---

## 7. False Positive Possibilities

Bu bulgular her zaman gerçek saldırı anlamına gelmez.

Olası false positive nedenleri:

* Kullanıcı şifresini yanlış girmiş olabilir.
* Admin veya güvenlik ekibi test yapıyor olabilir.
* Otomatik vulnerability scanner çalışıyor olabilir.
* İnternet botları genel pathleri tarıyor olabilir.
* IP adresi NAT veya proxy arkasından geliyor olabilir.
* Geliştirici test sırasında SQLi/XSS benzeri payload göndermiş olabilir.

---

## 8. Recommended SOC Actions

SOC analyst olarak önerilen sonraki adımlar:

1. Kaynak IP adreslerinin iç ağ mı dış ağ mı olduğu kontrol edilir.
2. `172.16.10.20` IP adresinden yapılan başarılı login kullanıcıya doğrulatılır.
3. `203.0.113.55` IP adresi firewall, WAF ve proxy loglarında aranır.
4. Web isteklerinden sonra başarılı işlem, 200 veya 500 response artışı olup olmadığı incelenir.
5. SSH başarısız denemelerinden sonra başarılı giriş olup olmadığı kontrol edilir.
6. Gerekirse ilgili kullanıcıların parolaları resetlenir.
7. Şüpheli IP adresleri blocklist’e alınabilir.
8. Aynı IP adreslerinin başka sistemlere erişip erişmediği kontrol edilir.
9. EDR veya endpoint logları ile süreç derinleştirilir.
10. Tespit mantıkları SIEM kuralına dönüştürülür.

---

## 9. Detection Ideas

Bu analizden çıkarılabilecek detection fikirleri:

```text
5 dakika içinde aynı IP’den 5+ failed SSH login
Aynı IP’den 4+ farklı kullanıcıya failed login
3+ failed login sonrası successful login
Aynı IP’den 5+ HTTP 404 response
/admin, /.git, /backup.zip, /wp-login.php path denemeleri
SQLi marker: ' OR 1=1, UNION SELECT
XSS marker: <script>, onerror=, javascript:
Aynı IP’nin hem auth hem web loglarında şüpheli davranış göstermesi
```

---

## 10. Lessons Learned

Bu çalışma sonucunda şunlar öğrenilmiştir:

* Tek bir log kaynağı olayın tamamını göstermeyebilir.
* Auth logları login davranışlarını anlamak için önemlidir.
* Web access logları reconnaissance ve web attack denemelerini gösterebilir.
* Failed login sonrası successful login daha kritik değerlendirilmelidir.
* Aynı IP’nin birden fazla log kaynağında görünmesi olayın riskini artırır.
* SOC analyst için korelasyon, basit log sayımından daha değerlidir.
* Detection yazarken false positive ihtimalleri mutlaka düşünülmelidir.

---

## 11. Conclusion

Bu mini SOC case çalışmasında Linux SSH auth logları ve web access logları analiz edilerek brute force, password spraying, web path scan, SQL injection, XSS ve çok kaynaklı korelasyon bulguları incelenmiştir.

En kritik bulgular:

```text
172.16.10.20 -> failed login sonrası successful login
203.0.113.55 -> hem SSH failed login hem web path scan
```

Bu çalışma, temel SOC analizi için ilk portföy projesi olarak kullanılabilir.

