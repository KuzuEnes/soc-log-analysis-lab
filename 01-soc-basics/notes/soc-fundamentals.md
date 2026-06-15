# SOC Fundamentals

## SOC Nedir?

SOC, Security Operations Center anlamına gelir. Kurumun güvenlik olaylarını izleyen, analiz eden ve gerektiğinde müdahale sürecini başlatan ekiptir.

## Alert Nedir?

Alert, güvenlik sistemlerinin şüpheli veya riskli gördüğü olaylar için ürettiği uyarıdır.

## False Positive Nedir?

Sistemin şüpheli sandığı ama aslında zararsız olan olaydır.

Örnek:
- Kullanıcının şifresini birkaç kez yanlış girmesi
- Adminin bakım sırasında çok sayıda bağlantı yapması
- Güvenlik tarama aracının normal test trafiği üretmesi

## True Positive Nedir?

Gerçekten riskli veya zararlı olan olaydır.

Örnek:
- Kısa sürede çok sayıda başarısız login
- Web sunucusuna SQL injection payload gönderilmesi
- PowerShell ile şüpheli komut çalıştırılması

## SOC Analyst İlk Bakışta Neye Bakar?

1. Alert ne söylüyor?
2. Hangi kullanıcı etkilenmiş?
3. Hangi IP adresi kaynak?
4. Hangi sistem hedef?
5. Olay ne zaman olmuş?
6. Tek olay mı, zincirin parçası mı?
7. Normal kullanıcı davranışı olabilir mi?
8. MITRE ATT&CK karşılığı var mı?
