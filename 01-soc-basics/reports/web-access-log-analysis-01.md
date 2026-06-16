# Web Access Log Analysis 01

## Amaç

Bu çalışmada web access logları üzerinde şüpheli web davranışları analiz edilmiştir.

İncelenen davranışlar:

- Web path scan
- Directory enumeration
- SQL injection markerları
- XSS markerları

## Log Kaynağı

- Dosya: `01-soc-basics/data/access.log`
- Log türü: Web server access log

## Tespit 1: Web Path Scan / Directory Scan

`203.0.113.55` IP adresinden kısa süre içinde birçok şüpheli path denenmiştir:

```text
/admin
/wp-login.php
/.git/config
/backup.zip
/phpinfo.php
/config.php
