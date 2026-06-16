# Auth Log Analysis 02

## Amaç

Bu çalışmada Linux SSH auth logları üzerinde daha gelişmiş bir analiz yapılmıştır.

İlk analizde sadece başarısız giriş sayıları incelenmişti. Bu çalışmada ek olarak şu davranışlar araştırılmıştır:

- Brute force
- Password spraying
- Başarısız girişlerden sonra başarılı giriş

## Log Kaynağı

- Dosya: `01-soc-basics/data/auth.log`
- Log türü: Linux SSH authentication log

## Tespit 1: Brute Force Şüphesi

`192.168.1.50` IP adresinden `admin` kullanıcısına kısa sürede 6 başarısız giriş denemesi yapılmıştır.

Bu davranış brute force saldırısına işaret edebilir.

## Tespit 2: Password Spraying Şüphesi

`203.0.113.8` IP adresinden farklı kullanıcı adlarına başarısız giriş denemeleri yapılmıştır:

```text
ali
veli
ayse
mehmet
