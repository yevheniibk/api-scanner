# API Security Scanner

Автоматизований сканер вразливостей для REST API, побудований на базі Postman-колекцій.
Перевіряє три категорії з [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x00-header/).

Розроблений і протестований на [VAmPI](https://github.com/erev0s/VAmPI) — навмисно вразливому REST API.

---

## Вміст

- [Вимоги](#вимоги)
- [Швидкий старт](#швидкий-старт)
- [Що перевіряє сканер](#що-перевіряє-сканер)
- [Конфігурація](#конфігурація)
- [Як читати звіт](#як-читати-звіт)
- [JSON-звіт](#json-звіт)
- [Інтеграція з GitHub Actions](#інтеграція-з-github-actions)
- [Архітектура](#архітектура)
- [Відомі обмеження](#відомі-обмеження)

---

## Вимоги

- Python 3.10+
- `pip install requests`
- Запущений VAmPI на `http://127.0.0.1:5000`
- Файл `VAmPI.postman_collection.json` поряд зі `scanner.py`

---

## Швидкий старт

```bash
# 1. Запустити VAmPI
git clone https://github.com/erev0s/VAmPI.git
cd VAmPI && pip install -r requirements.txt && python app.py &

# 2. Запустити сканер
cd ..
pip install requests
python scanner.py
```

Після завершення в консолі буде звіт, а у файлі `scan_report.json` — машинозчитувана версія.

**Exit codes:**
- `0` — вразливостей не знайдено
- `1` — знайдено хоча б один `FAIL` або критична помилка запуску

---

## Що перевіряє сканер

### 1. Excessive Data Exposure (API3:2023)

Перевіряє всі `GET`-ендпоінти: якщо у відповіді є поля з набору чутливих імен — це `FAIL`.

Чутливі поля за замовчуванням:

```
password, token, auth_token, secret, hash, debug
```

Логіка: `GET`-запит з валідним токеном (для bearer-ендпоінтів) або без токена → аналіз тіла відповіді.

---

### 2. Broken Authentication (API2:2023)

Перевіряє всі ендпоінти, позначені в Postman як `bearer`-захищені.

Два тест-кейси на кожен ендпоінт:

| Тест | Очікуваний результат |
|------|----------------------|
| Запит без токена | `401 / 403 / 404` |
| Запит з невалідним токеном `invalid.token.value` | `401 / 403 / 404` |

Якщо ендпоінт повертає успішний статус — `FAIL`. Якщо повертає інший статус (не `2xx` і не `401/403/404`) — `REVIEW`.

---

### 3. BOLA / IDOR (API1:2023)

Перевіряє ендпоінти, де в URL є ідентифікатор ресурсу (`:username`, `:book_title` тощо).

Сценарій: атакуючий (`name2`) надсилає запит з **власним токеном**, але використовує **ідентифікатор жертви** (`name1`) у шляху або тілі. Якщо відповідь успішна — `FAIL`.

Методи: `GET`, `PUT`, `PATCH`. `DELETE` вимкнений за замовчуванням (деструктивний).

---

## Конфігурація

Всі налаштування — константи у верхній частині `scanner.py`.

### Основні

| Константа | За замовчуванням | Опис |
|-----------|-----------------|------|
| `BASE_URL` | `http://127.0.0.1:5000` | Базова URL VAmPI |
| `POSTMAN_COLLECTION_FILE` | `VAmPI.postman_collection.json` | Шлях до колекції |
| `REQUEST_TIMEOUT` | `10` | Таймаут кожного HTTP-запиту (секунди) |

### Тестові дані

```python
ATTACKER = {"username": "name2", "password": "pass2", "email": "mail2@mail.com"}
VICTIM   = {"username": "name1", "password": "pass1", "email": "mail1@mail.com"}
VICTIM_BOOK = {"book_title": "bookTitle77", "secret": "secret for bookTitle77"}
```

Відповідають стандартній базі VAmPI після `/createdb`.

### Виключення зі сканування

```python
EXCLUDED_SCAN_PATHS = {"/createdb"}
```

Ендпоінти з цього набору завжди пропускаються — вони змінюють стан БД і не є цілями для аудиту.

### Ввімкнути деструктивний BOLA (DELETE)

```python
ENABLE_DESTRUCTIVE_BOLA = False  # змінити на True
```

> ⚠️ Вмикати тільки у відновлюваному середовищі — DELETE справді видаляє дані.

### Чутливі поля (Data Exposure)

```python
SENSITIVE_FIELDS = {"password", "token", "auth_token", "secret", "hash", "debug"}
```

Додавайте власні поля за потреби.

---

## Як читати звіт

```
- GET /books/v1/bookTitle77
  name: Retrieves book by title along with secret
  url: http://127.0.0.1:5000/books/v1/bookTitle77
  bola: FAIL
    http_status: 200
    reason: Attacker accessed or modified victim-owned object
    evidence:
      - Attacker username: name2
      - Victim username: name1
      - Response preview: {"secret": "secret for bookTitle77", ...}
  auth: PASS
    reason: Missing and invalid tokens were rejected
  data: FAIL
    http_status: 200
    reason: Response exposes sensitive fields
    evidence:
      - Sensitive fields found: secret
```

### Статуси

| Статус | Значення |
|--------|----------|
| `FAIL` | Вразливість підтверджена — потребує виправлення |
| `PASS` | Перевірка пройдена |
| `REVIEW` | Неоднозначна відповідь — потребує ручної перевірки |
| `N/A` | Перевірка не застосовується до цього ендпоінту |

### Підсумок

```
endpoints: 14        ← загальна кількість ендпоінтів у колекції
executed checks: 16  ← реально виконаних перевірок (без N/A)
fail: 5
pass: 11
review: 0
not applicable: 26
```

---

## JSON-звіт

Після кожного запуску сканер зберігає `scan_report.json`:

```json
{
  "endpoints": [
    {
      "method": "GET",
      "path": "/books/v1/bookTitle77",
      "name": "Retrieves book by title along with secret",
      "url": "http://127.0.0.1:5000/books/v1/bookTitle77",
      "excluded": false,
      "checks": {
        "bola": {
          "status": "FAIL",
          "http_status": 200,
          "reason": "Attacker accessed or modified victim-owned object",
          "evidence": ["..."]
        },
        "auth": { "status": "PASS", ... },
        "data": { "status": "FAIL", ... }
      }
    }
  ],
  "summary": {
    "endpoints": 14,
    "executed_checks": 16,
    "fail": 5,
    "pass": 11,
    "review": 0,
    "not_applicable": 26
  }
}
```

---

## Інтеграція з GitHub Actions

Помістіть файл `.github/workflows/api-security-scan.yml` у репозиторій.

### Структура репозиторію

```
repo/
├── scanner.py
├── requirements.txt                   # requests
├── VAmPI.postman_collection.json
└── .github/
    └── workflows/
        └── api-security-scan.yml
```

### Тригери

| Тригер | Поведінка |
|--------|-----------|
| `push` до `main` / `develop` | Запуск сканування |
| `pull_request` до `main` | Запуск + коментар з результатами у PR |
| `schedule` (щодня о 3:00 UTC) | Нічна перевірка регресій |
| `workflow_dispatch` | Ручний запуск через GitHub UI |

### Що робить workflow

1. Клонує VAmPI і запускає його у фоні
2. Очікує готовності сервера (health check, 15 спроб)
3. Запускає `python scanner.py`
4. Зберігає `scan_report.json` як артефакт (зберігається 30 днів)
5. При PR — публікує таблицю результатів у коментарі

### Exit code і блокування merge

`scanner.py` завершується з кодом `1` якщо є хоча б один `FAIL`. Workflow правильно інтерпретує це як провал — merge буде заблокований до усунення вразливостей (якщо увімкнений branch protection).

---

## Архітектура

```
scanner.py
│
├── CONFIG                    # константи, тестові дані, набори статусів
│
├── MODELS
│   ├── Endpoint              # незмінний датаклас, описує один запит з колекції
│   └── CheckResult           # результат однієї перевірки (статус + докази)
│
├── HTTP CLIENT
│   ├── send_request()        # базовий HTTP-клієнт, керує токеном і тілом
│   └── send_endpoint_request() # надсилає запит для конкретного Endpoint
│
├── VAMPI SETUP
│   ├── setup_vampi()         # скидання БД → реєстрація → логін → книга
│   ├── _register_user()      # ідемпотентна реєстрація
│   ├── _create_victim_book() # ідемпотентне створення книги-цілі для BOLA
│   └── login_user()          # логін, повертає auth_token
│
├── POSTMAN PARSING
│   ├── load_postman_collection()  # рекурсивний обхід колекції
│   ├── parse_postman_request()    # перетворює Postman item → Endpoint
│   ├── parse_postman_body()       # raw / urlencoded / formdata
│   ├── extract_path_variables()   # витягує :змінні, підставляє HARDCODED_VALUES
│   ├── extract_postman_path()     # повертає шаблонний шлях (/users/v1/:username)
│   └── resolve_postman_url()      # підставляє {{змінні}} і :змінні у URL
│
├── SCAN HELPERS
│   ├── short_response_preview()   # обрізає відповідь до 500 символів
│   ├── find_sensitive_fields()    # рекурсивний пошук чутливих ключів у JSON
│   └── build_bola_body()          # формує тіло запиту для BOLA-тесту
│
├── SCANS
│   ├── scan_data_exposure()  # GET-ендпоінти → пошук чутливих полів
│   ├── scan_auth()           # bearer-ендпоінти → тест без токена і з невалідним
│   └── scan_bola()           # ендпоінти з ідентифікаторами → запит від атакуючого
│
├── REPORT
│   ├── print_endpoint_report() # консольний звіт + запис scan_report.json
│   └── print_check_result()    # форматування одного результату перевірки
│
└── main()                    # точка входу, exit 1 при FAIL
```

---

## Відомі обмеження

- **Тільки VAmPI** — тестові дані (`ATTACKER`, `VICTIM`, `VICTIM_BOOK`) захардкоджені під VAmPI. Для іншого API потрібно переписати секцію CONFIG і `setup_vampi()`.
- **Postman-колекція як єдине джерело** — OpenAPI/Swagger не підтримується навмисно.
- **Послідовне виконання** — запити йдуть один за одним; на великих колекціях буде повільно.
- **BOLA тільки за ідентифікатором у шляху** — BOLA через тіло запиту або заголовки не перевіряється.
- **Автентифікація тільки Bearer** — Basic Auth, API Key та інші схеми ігноруються.
- **DELETE вимкнений за замовчуванням** — `ENABLE_DESTRUCTIVE_BOLA = False`.
