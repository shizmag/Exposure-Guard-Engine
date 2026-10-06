# ExposureGuard

## 1. Идея продукта

**ExposureGuard — сервис непрерывного контроля публичной поверхности интернет-проекта.**

Пользователь добавляет принадлежащие ему ресурсы:

- сайт;
- домен;
- поддомены;
- Telegram Mini App;
- в дальнейшем — Telegram Bot, GitHub repository, API и другие типы assets.

ExposureGuard смотрит на проект **так, как его можно увидеть снаружи**, сохраняет baseline и сообщает владельцу, когда появляется новое потенциально опасное exposure.

Главное обещание:

> Узнайте первым, если после очередного деплоя или изменения инфраструктуры наружу попало то, что не должно было.

Продукт не позиционируется как автоматический pentest и не пытается заменить security-команду.

Это **continuous external exposure monitoring**.

---

# 2. Какую проблему решаем

У небольших интернет-проектов регулярно меняется публичная поверхность:

- выкатываются новые версии frontend;
- появляются и исчезают поддомены;
- создаются staging/debug environments;
- меняются DNS records;
- подключаются сторонние сервисы;
- меняются JavaScript bundles;
- случайно публикуются source maps;
- в frontend могут попасть credentials или внутренние endpoints;
- появляется забытый development host;
- меняются TLS certificates;
- появляются новые misconfigurations.

Большинство небольших команд узнаёт об этом одним из трёх способов:

1. случайно;
2. после сообщения от пользователя или security researcher;
3. уже после инцидента.

Существующие security-инструменты часто либо:

- рассчитаны на специалистов;
- ориентированы на enterprise;
- выдают огромный список findings;
- требуют отдельного security-процесса;
- либо являются разовыми scanners без понятного monitoring workflow.

ExposureGuard должен закрывать более простой JTBD:

> **«У меня есть интернет-проект. Следи за тем, что торчит наружу, и скажи мне простыми словами, если произошло что-то важное».**

---

# 3. Что пользователь покупает на самом деле

Пользователь покупает не количество security checks.

Он покупает:

### Visibility

Что вообще сейчас публично доступно у моего проекта?

### Change detection

Что появилось с прошлого сканирования?

### Prioritisation

На что мне действительно стоит обратить внимание?

### Evidence

Почему сервис считает это проблемой?

### Notification

Сообщите мне сразу, а не тогда, когда я случайно зайду в dashboard.

### History

Когда проблема появилась и когда была исправлена?

Поэтому фундаментальная продуктовая модель:

**Discover → Baseline → Monitor → Diff → Explain → Alert**

а не:

**Scan → 147 vulnerabilities → PDF**

---

# 4. Что технически делает продукт

В самом простом виде пользователь добавляет:

`example.com`

ExposureGuard:

1. определяет разрешённую публичную поверхность;
2. находит связанные assets;
3. проверяет DNS/TLS/HTTP;
4. обнаруживает публичные поддомены;
5. аккуратно crawl'ит сайт;
6. собирает публичные JavaScript bundles;
7. обнаруживает source maps;
8. анализирует публичные frontend assets на потенциальные exposures;
9. запускает безопасный набор exposure/misconfiguration checks;
10. нормализует findings разных security engines;
11. объединяет дубликаты;
12. сохраняет состояние;
13. при следующем сканировании сравнивает его с предыдущим;
14. уведомляет пользователя о значимых изменениях.

Под капотом могут использоваться специализированные OSS scanners.

Пользователь этого уровня абстракции видеть не должен.

Он видит:

> **New production source map detected after today's deployment.**

а не:

> `nuclei template X + katana output Y + custom detector Z`.

---

# 5. Главная продуктовая единица

Основная сущность — **Project**.

Например:

### Consumora Website

`consumora.ru`

Type:

`Website`

### Consumora Domain

`consumora.ru`

Type:

`Domain`

### Consumora Mini App

`@consumora_bot`

Type:

`Telegram Mini App`

Позже:

- Repository;
- API;
- Telegram Bot;
- WordPress;
- Shopify;
- Crypto Project;
- Cloud Account.

Разным Project Types соответствуют разные наборы scanner packs.

---

# 6. Первичная целевая аудитория

Не нужно сразу продавать «всем малым компаниям».

Первоначальная аудитория должна быть технически достаточно зрелой, чтобы понимать ценность продукта, но недостаточно большой, чтобы иметь собственную security-команду.

## ICP 1 — Indie hackers / solo developers

Типичный клиент:

- 1–10 интернет-проектов;
- Next.js/React/Vue;
- Vercel/Cloudflare/VPS;
- GitHub;
- несколько доменов;
- постоянно что-то выкатывает;
- security engineer отсутствует.

Его JTBD:

> «Я быстро выкатываю продукт и хочу быть уверен, что случайно не выставил что-нибудь наружу».

---

## ICP 2 — маленькие SaaS-команды

Примерно:

- 2–30 сотрудников;
- публичное web-приложение;
- несколько environments;
- активная разработка;
- инфраструктура постоянно меняется;
- полноценного AppSec/SOC нет.

JTBD:

> «Мне нужен минимальный постоянный security контроль без покупки enterprise-security stack».

---

## ICP 3 — Web / Dev agencies

Очень интересная аудитория.

У агентства может быть:

- 20;
- 50;
- 200+

клиентских сайтов.

Проблема уже не только security, а **невозможность вручную следить за всем estate**.

JTBD:

> «Сообщите мне, если на любом клиентском проекте появилось что-то подозрительное».

Потенциально именно Agency может стать самым дорогим тарифом.

---

## ICP 4 — Telegram / crypto / internet-native проекты

Интересны из-за сочетания:

- высокая стоимость credential leaks;
- Telegram как рабочая среда;
- привычка к USDT;
- Telegram Mini Apps/Bots;
- быстрые deployment cycles.

Этот сегмент особенно удобен как первоначальный distribution wedge.

Но сам продукт **не ограничивается Telegram**.

---

# 7. Рынок и конкуренция

Важно не обманывать себя:

**рынок external attack surface/security monitoring уже существует, и он не пустой.**

На нём есть как enterprise-продукты, так и новые SMB/self-service проекты.

Например:

- SurfaceLoop предлагает EASM для small businesses примерно от £149/мес;
- wye scan предлагает self-service monitoring примерно от $25/мес;
- WebDefect продаёт continuous attack-surface/security monitoring от $19/мес;
- WebHound предлагает continuous website security monitoring от $29/мес.

Кроме того, появляется много бесплатных scanner-first продуктов. Например Exposd уже проверяет headers, cookies, source maps и JS secret patterns, а EchelonGraph предлагает несколько десятков бесплатных checks.

Следовательно, наша гипотеза не должна звучать:

> «Конкурентов нет».

Она должна звучать:

> **Существует место для очень простого product-led security monitoring продукта, который получает пользователей через сеть бесплатных security utilities, ориентируется на small internet projects и использует Telegram как alert/distribution layer.**

Это и нужно валидировать.

---

# 8. Позиционирование

Не:

> All-in-one cybersecurity platform.

Не:

> Automated penetration testing.

Не:

> AI-powered security scanner.

Не:

> Vulnerability management platform.

Первоначальное positioning:

> **Know when your project accidentally becomes exposed.**

RU:

> **Узнайте первым, если ваш интернет-проект случайно выставил что-то наружу.**

Более утилитарный вариант:

> **Continuous security monitoring for things you expose by accident.**

---

# 9. Основное конкурентное отличие

Мы не должны пытаться выиграть количеством checks.

Нужно выигрывать моделью продукта.

## 9.1. Change-first

Главный вопрос:

> **Что изменилось?**

а не:

> «Какие 312 потенциальных проблем существуют вообще?»

---

## 9.2. Low-noise

Лучше:

`3 findings`

которые пользователь действительно понимает,

чем:

`273 findings`.

---

## 9.3. Evidence-first

Каждая проблема должна иметь:

- affected asset;
- evidence;
- время первого обнаружения;
- источник;
- объяснение;
- remediation.

---

## 9.4. Telegram-first notifications

Dashboard нужен для исследования.

Telegram нужен для реальной эксплуатации.

Пример:

> 🔴 New exposure  
> Public production source map appeared on `app.example.com` 4 minutes ago.

---

## 9.5. Простая покупка

Без enterprise sales.

Самостоятельная регистрация.

Оплата:

- ₽ / СБП / российские карты на web;
- USDT для соответствующей international/crypto-аудитории;
- Telegram Stars для цифровых услуг, продаваемых непосредственно внутри Telegram.

Telegram официально требует Stars для digital goods/services, продаваемых внутри bot/Mini App.

---

# 10. Distribution thesis

Это одна из самых важных частей всего бизнеса.

Мы не хотим зависеть исключительно от:

- платной рекламы;
- outbound;
- продаж;
- одного лендинга.

Вместо этого ExposureGuard должен постепенно построить **сеть самостоятельных бесплатных security-сервисов**.

Каждый решает одну маленькую задачу и сам способен собирать поисковый/community traffic.

Все они ведут в один основной продукт.

Это модель:

**Free Utility → Useful Result → ExposureGuard → Continuous Monitoring**

---

# 11. Бесплатные сервисы как acquisition network

Не обязательно выпускать всё сразу.

Но архитектура бренда должна позволять иметь десятки маленьких tools.

## Website Security Scanner

`/tools/website-security-scanner`

Самый широкий вход.

---

## Security Headers Checker

`/tools/security-headers`

Проверяет:

- CSP;
- HSTS;
- X-Frame-Options;
- Permissions-Policy;
- Referrer-Policy;
- и т. д.

Подобная модель уже используется продуктами вроде HeaderHawk, который объединяет основной scanner и набор отдельных бесплатных browser/security utilities.

---

## Source Map Exposure Checker

`/tools/source-map-checker`

Очень конкретный запрос.

Показывает:

- обнаружены ли production source maps;
- содержат ли они source content;
- какие bundles затронуты.

CTA:

> Monitor source-map exposure continuously.

---

## JavaScript Secret Scanner

`/tools/js-secret-scanner`

Публичный статический анализ frontend JavaScript.

Никакой validation credentials.

---

## TLS Checker

`/tools/tls-checker`

Сертификат, срок действия, базовые проблемы.

---

## CSP Analyzer

`/tools/csp-analyzer`

Можно поддерживать два режима:

- URL;
- вставить CSP вручную.

---

## Cookie Security Checker

`/tools/cookie-security`

Secure / HttpOnly / SameSite.

---

## CORS Checker

`/tools/cors-checker`

Только безопасные проверки конфигурации.

---

## DNS Exposure Checker

`/tools/dns-security`

DNS/CAA/DNSSEC и публичная инфраструктура.

---

## Subdomain Surface Scanner

`/tools/subdomains`

Показывает публично обнаруживаемую поверхность домена.

---

## `.git / .env Exposure Checker`

Узкий scanner для нескольких часто случайно опубликованных artefacts.

---

## Telegram Mini App Security Checker

`/tools/telegram-mini-app-security`

Это очень хороший Telegram/Habr acquisition wedge.

---

## Redirect Security Checker

Проверяет redirect chain и потенциально подозрительные переходы.

---

Со временем может быть **20–50 подобных tools**.

Но важно:

> Это не 50 отдельных продуктов.

Это 50 acquisition surfaces над **одним scanner infrastructure**.

---

# 12. Почему эта модель distribution интересна

Каждый free tool:

1. имеет отдельный landing;
2. закрывает конкретный search intent;
3. даёт результат без регистрации;
4. легко распространяется ссылкой;
5. может иметь программно генерируемые explanatory pages;
6. использует общий backend/scanning engine;
7. приводит пользователя в основной monitoring product.

Получается своеобразный **tool-based SEO moat**.

Например человек ищет:

`check source maps website`

а не:

`external attack surface management platform`.

Нам выгоднее поймать его на первом запросе.

---

# 13. Основная воронка

## Step 1 — Free utility

Пользователь вводит:

`myproject.com`

---

## Step 2 — Instant value

Получает:

> 18 checks complete  
> 2 exposures found.

Регистрация пока не обязательна.

---

## Step 3 — Conversion

CTA:

> **Protect this project continuously**

---

## Step 4 — Account

Создаётся Project.

Сохраняется baseline.

---

## Step 5 — Telegram

CTA:

> **Get security alerts in Telegram**

Это одновременно activation и retention mechanism.

---

## Step 6 — Paid

Причины upgrade:

- больше проектов;
- больше assets;
- более частое сканирование;
- история;
- repository integration;
- дополнительные packs;
- agency features.

---

# 14. Каналы распространения

## SEO

Потенциально главный scalable channel.

Не один landing, а целая экосистема:

`/tools/*`

`/checks/*`

`/fix/*`

`/guides/*`

Например:

- CSP checker;
- exposed source maps;
- public .git;
- HSTS checker;
- Next.js security headers;
- Vercel source maps;
- Telegram Mini App security;
- etc.

---

## Habr

Очень сильный канал благодаря возможности публиковать **собственные исследования**.

Не маркетинговые статьи:

> «Купите ExposureGuard».

А:

> «Мы просканировали 10 000 сайтов и посмотрели, сколько из них публикуют source maps».

> «Какие credentials разработчики оставляют в production JavaScript».

> «Что видно о вашем Next.js-проекте снаружи».

---

## Hacker News

Подходит для:

- Show HN;
- open-source scanner components;
- технических исследований;
- unusual datasets;
- deep technical posts.

---

## vc.ru

Более прикладной контент:

> «Как небольшому SaaS следить за безопасностью без отдельного специалиста».

---

## Telegram

Два уровня.

### Content

Свой security/dev канал.

### Utility

Бот:

`/scan domain.com`

→ маленький scan.

И затем:

> Continuous monitoring →

---

## GitHub

Часть маленьких scanner components можно публиковать open-source.

Например:

- JS exposure detector;
- source-map inspector;
- safe scanner rules.

GitHub становится acquisition channel, а hosting/history/monitoring остаются SaaS.

---

## Agencies

Отдельный B2B2B-channel.

Агентство использует ExposureGuard для клиентов.

Каждый клиентский report:

> Protected by ExposureGuard

может приводить следующего пользователя.

---

# 15. Монетизация

Первоначально модель должна оставаться очень простой.

## Free

**0 ₽**

Например:

- 1 project;
- ограниченное количество assets;
- daily scan;
- ограниченная history;
- основные external checks;
- Telegram alerts.

Free существует не как crippled demo, а как реальный продукт.

---

## Pro

Гипотеза:

**~990–1 990 ₽/мес**

или соответствующий USDT price.

Например:

- 5 projects;
- 50 assets;
- hourly monitoring;
- 90-day history;
- extended scanner packs;
- Telegram alerts;
- repository integration.

Точную цену нужно проверять отдельно.

---

## Agency

Гипотеза:

**~4 990–9 990 ₽/мес**

Например:

- 30+ projects;
- сотни assets;
- client grouping;
- team;
- reports;
- long history;
- priority scanning.

---

# 16. One-off monetisation

Подписка не обязана быть единственным способом заплатить.

Очень интересный продукт:

> **Deep Security Scan**

Например:

`499–1 490 ₽`

или Stars.

Пользователь не должен сразу принимать решение:

> «Хочу ещё один SaaS subscription».

Он может купить конкретный результат.

После нескольких scans:

> You've scanned this project three times.  
> Continuous monitoring is cheaper.

Получается естественный upgrade path.

---

# 17. Telegram Stars

Stars особенно хорошо подходят для:

- разового scan;
- Telegram Mini App Security Audit;
- domain/security check;
- небольших дополнительных reports.

Например:

`@ExposureGuardBot`

Пользователь:

`/scan example.com`

Получает бесплатную preview.

> 3 potential exposures detected.

**Full scan — ⭐**

Telegram позволяет bot'ам продавать такие digital services через Stars и поддерживает invoice flow прямо внутри Telegram.

---

# 18. ₽

Основной rail для российской web-аудитории:

- карты;
- СБП.

Особенно для:

- разработчиков;
- агентств;
- небольших компаний.

---

# 19. USDT

Внешний payment rail для:

- crypto projects;
- international freelancers;
- webmasters;
- internet-native teams.

Это не должно быть gimmick.

Мы специально ищем аудиторию, для которой такой способ расчёта нормален.

---

# 20. Что формирует recurring value

Очень важный вопрос:

> Почему пользователь заплатит второй месяц?

Не потому что ему снова хочется security report.

А потому что постоянно меняется проект:

`deploy`

→ новая frontend версия;

`DNS change`

→ новый asset;

`new subdomain`

→ новая surface;

`dependency`

→ новое поведение;

`config`

→ новое exposure.

Следовательно:

**subscription = monitoring изменений.**

Разовый scan является acquisition/entry product.

---

# 21. Что является moat

На старте moat практически отсутствует.

OSS scanners доступны всем.

Поэтому moat нужно постепенно строить из:

## Historical state

Мы знаем, как выглядел проект вчера.

---

## Finding correlation

Несколько scanner signals превращаются в один meaningful finding.

---

## Low false-positive rate

Пользователь доверяет notification.

---

## Proprietary rule packs

Telegram, Next.js, Vercel, Shopify и другие специализированные packs.

---

## Dataset

Со временем появляется агрегированное понимание:

- какие exposures встречаются;
- какие действительно исправляются;
- какие patterns характерны для разных stacks;
- какие изменения чаще приводят к проблемам.

---

## Distribution network

Десятки бесплатных tools и высокоранжирующихся страниц сами становятся активом.

Это потенциально даже более сильный moat раннего бизнеса, чем scanning technology.

---

# 22. Чего продукт сознательно НЕ делает

На ранней стадии ExposureGuard — не:

- pentest company;
- bug bounty platform;
- SOC;
- SIEM;
- EDR;
- WAF;
- antivirus;
- malware sandbox;
- employee security platform;
- compliance suite;
- cloud-security platform;
- exploit framework.

Мы следим за **публичной поверхностью собственных проектов пользователя**.

---

# 23. Принцип безопасности

Сервис должен быть defensively scoped.

По умолчанию:

- passive discovery;
- публичные HTTP resources;
- static analysis;
- safe read-only checks;
- ограниченный crawling.

Более глубокие проверки требуют подтверждения владения.

Никакой автоматической эксплуатации найденных проблем.

---

# 24. Каким может стать продукт потом

Начало:

**Website + Domain**

↓

**Telegram Mini App**

↓

**Git Repository**

↓

**Telegram Bot / API**

↓

**specialised scanner packs**

↓

**Agency estate monitoring**

↓

потенциально полноценная:

> **Security monitoring platform for small internet businesses.**

Telegram остаётся:

- distribution channel;
- alert surface;
- payment surface;
- одним из project types;

но не ограничивает рынок.

---

# 25. Главная business hypothesis

Мы предполагаем, что существует аудитория небольших internet-first проектов, которой:

- уже недостаточно бесплатного одноразового scanner;
- слишком рано покупать enterprise AppSec/EASM;
- хочется понятного continuous monitoring;
- важнее изменения и alerts, чем огромная vulnerability database.

Эта гипотеза ещё **не доказана**.

Именно её должен валидировать первый публичный продукт.

---

# 26. Главная distribution hypothesis

Можно построить acquisition machine вокруг:

> **множества бесплатных security utilities на общей scanning infrastructure.**

Вместо покупки каждого пользователя рекламой мы постепенно создаём:

- SEO footprint;
- reusable tools;
- shareable reports;
- research data;
- GitHub presence;
- Telegram utility;
- technical content.

И все дороги ведут в:

> **Monitor this project continuously.**

---

# 27. Как должен ощущаться продукт

Не как корпоративная security console.

Не:

`CVE-2026-XXXX CVSS 6.4 CWE-...`

как основной интерфейс.

А:

> **Something new became public after yesterday's deploy.**

Security evidence остаётся внутри finding для технического пользователя.

Основной UX:

**спокойный, понятный, доказательный.**

---

# 28. Ключевая формула продукта

### Бесплатное

**Check**

↓

### Activation

**Protect**

↓

### Retention

**Monitor**

↓

### Value moment

**Something changed**

↓

### Delivery

**Telegram alert**

↓

### Paid

**More projects + faster monitoring + deeper checks**

---

# 29. Наиболее важные метрики

## Acquisition

- free tool visits;
- scans initiated;
- scan completion rate;
- organic traffic;
- share rate.

## Activation

- free scan → account;
- account → first protected project;
- project → Telegram connection.

## Value

- new meaningful exposures detected;
- percentage of findings resolved;
- median detection latency.

## Retention

- protected projects active after 30/90 days;
- Telegram alert engagement;
- repeated scans.

## Revenue

- free → Pro;
- one-off → subscription;
- MRR;
- ARPPU;
- projects per account;
- Agency share.

---

# 30. North Star

**Protected Active Projects**

Project считается protected, если:

- подтверждён;
- monitoring включён;
- последний scan успешно завершён;
- он находится внутри допустимой freshness window.

Это отражает реальную работу, которую выполняет ExposureGuard.

---

# 31. Что сейчас необходимо проверить рынком

До того как считать концепцию окончательной, нужно проверить минимум пять гипотез.

### H1

Людей волнует **continuous exposure change**, а не только разовый security scan.

### H2

Telegram alerts действительно увеличивают retention.

### H3

Бесплатные узкие scanners способны давать дешёвый qualified traffic.

### H4

Пользователь готов платить примерно 1–2 тыс. ₽/мес за несколько проектов без enterprise sales.

### H5

Agency-сегмент готов платить значительно больше за multi-client monitoring.

До проверки этих гипотез продукт остаётся бизнес-гипотезой, а не доказанным market fit.

---

# 32. Краткое определение

**ExposureGuard — product-led external security monitoring для небольших интернет-проектов.**

Он объединяет:

**free security utilities для привлечения трафика**

+

**continuous monitoring как основной SaaS**

+

**Telegram для доставки alerts и дистрибуции**

+

**Stars / ₽ / USDT как удобные для выбранной аудитории способы оплаты**

+

**specialised scanner packs как путь расширения продукта.**

Конечная цель — не построить самый глубокий vulnerability scanner.

Цель:

> **стать самым простым способом постоянно знать, что опасного стало публично доступно у твоего интернет-проекта.**
