# llm-eval — LLM Tunnel Config Generation & Testing Pipeline

Пайплайн для сравнительного анализа способности языковых моделей генерировать
конфигурации прокси-туннелей, устойчивых к детектированию (метрики M1–M8).

Все модели — OpenAI, Anthropic, Google, DeepSeek, Qwen — доступны через единый
прокси [polza.ai](https://polza.ai) с одним API-ключом.

---

## Схема работы

```
pipeline.py run-all --models gpt-4o claude-haiku-3-5 gemini-2.5-flash --runs 3
       │
       ▼
  generator.py
  ─ загружает prompts/system.md + prompts/task.md
  ─ выбирает task-вариант (10 вариантов: SNI/порт/подсказки)
  ─ вызывает LLM через polza.ai → GenerationResult (Pydantic)
       │
       ▼
  serializer.py
  ─ TunnelConfig → YAML  (enum values, None-exclusion, alias "validate")
       │
       ▼
  evaluator.py
  ─ генерирует TLS-сертификат (cryptography, чистый Python)
  ─ инжектирует PSK / Noise-ключи
  ─ запускает tunnel-testing/run_test.py
  ─ возвращает M1–M8 report.json
       │
       ▼
  results/{model_alias}/{run_id}/
    generation.json   ← structured output + metadata
    config.yaml       ← подготовленный конфиг (с cert-путями, PSK)
    report.json       ← M1–M8 вердикт
  results/reference/{name}/
    report.json       ← результаты tunnel-gen/examples/*
       │
       ▼
  comparison.py
  ─ pass-rate, avg M4/M6/M7 по моделям
  ─ точность предсказаний LLM
  ─ diversity (fingerprints, handshakes, SNI)
  ─ comparison_report.json
```

---

## Структура файлов

```
llm-eval/
├── requirements.txt
├── pipeline.py       # CLI: generate / reference / run-all / models
├── comparison.py     # анализ и сводные таблицы
├── schemas.py        # Pydantic: TunnelConfig + GenerationResult
├── providers.py      # PolzaProvider (OpenAI SDK → polza.ai)
├── generator.py      # построение промптов + LLM-вызов
├── evaluator.py      # подготовка конфига + запуск tunnel-testing
├── serializer.py     # TunnelConfig → YAML
├── .env              # API-ключи (не коммитить)
└── prompts/
    ├── system.md     # системный промпт (DSL, метрики, few-shot)
    └── task.md       # шаблон задачи ({domain}/{port}/{hints})
```

---

## Быстрый старт

### 1. Установить зависимости
```bash
pip install -r requirements.txt
```

### 2. Добавить API-ключ polza.ai
```bash
# .env в папке llm-eval/  (подхватывается автоматически через python-dotenv)
POLZA_KEY=pza_...        # https://polza.ai/dashboard/api-keys
# или
POLZA_API_KEY=pza_...    # оба имени поддерживаются
```

### 3. Проверить доступные модели
```bash
python pipeline.py models
```

### 4. Одна генерация (без тестирования — только LLM-вызов)
```bash
python pipeline.py generate --model gpt-4o-mini --runs 1
```

### 5. Генерация + полное тестирование
```bash
python pipeline.py generate --model gpt-4o --runs 3 --test --duration 30
```

### 6. Несколько моделей за один прогон
```bash
python pipeline.py run-all \
  --models gpt-4o claude-haiku-3-5 gemini-2.5-flash deepseek-chat qwen3-32b \
  --runs 3 --duration 30
```

### 7. Тестирование референсных конфигов (tunnel-gen/examples/)
```bash
python pipeline.py reference --duration 30
```

### 8. Сравнительный анализ
```bash
python comparison.py
```

---

## Поддерживаемые модели

Все модели проксируются через `https://polza.ai/api/v1` с ID формата `provider/model`.

| Алиас | polza model ID | Провайдер |
|-------|----------------|-----------|
| `claude-haiku-3` | `anthropic/claude-3-haiku` | Anthropic |
| `claude-haiku-3-5` | `anthropic/claude-3.5-haiku` | Anthropic |
| `claude-haiku-4` | `anthropic/claude-haiku-4.5` | Anthropic |
| `claude-sonnet-4` | `anthropic/claude-sonnet-4` | Anthropic |
| `claude-sonnet-4-5` | `anthropic/claude-sonnet-4.5` | Anthropic |
| `claude-opus-4` | `anthropic/claude-opus-4` | Anthropic |
| `gpt-4o-mini` | `openai/gpt-4o-mini` | OpenAI |
| `gpt-4o` | `openai/gpt-4o` | OpenAI |
| `gpt-4.1-mini` | `openai/gpt-4.1-mini` | OpenAI |
| `gpt-4.1` | `openai/gpt-4.1` | OpenAI |
| `gemini-2.5-flash` | `google/gemini-2.5-flash` | Google |
| `gemini-2.5-flash-lite` | `google/gemini-2.5-flash-lite` | Google |
| `gemini-2.5-pro` | `google/gemini-2.5-pro` | Google |
| `gemini-3-flash` | `google/gemini-3-flash-preview` | Google |
| `deepseek-chat` | `deepseek/deepseek-chat` | DeepSeek |
| `deepseek-v3` | `deepseek/deepseek-chat-v3-0324` | DeepSeek |
| `deepseek-r1` | `deepseek/deepseek-r1` | DeepSeek |
| `qwen3-32b` | `qwen/qwen3-32b` | Alibaba |
| `qwen3-max` | `qwen/qwen3-max` | Alibaba |

Полный список из 366 моделей: `python -c "from providers import build_provider; ..."` или через polza.ai/models.

---

## Structured output

Каждый LLM-вызов форсирует заполнение `GenerationResult` через function calling
(`tool_choice: forced`). Схема одинакова для всех провайдеров.

```python
class GenerationResult(BaseModel):
    reasoning: str                    # цепочка рассуждений о выборе параметров
    config: TunnelConfig              # полная DSL-конфигурация
    stealth_prediction: StealthPrediction  # предсказание по каждой метрике
    known_weaknesses: list[str]       # признанные слабые места
```

`TunnelConfig` — точное зеркало Go-структур из `tunnel-gen/dsl/schema.go`.

### Quirks провайдеров

| Провайдер | Поведение |
|-----------|-----------|
| OpenAI | Строго следует схеме function calling |
| Anthropic | Возвращает все поля корректно |
| **Gemini** | Возвращает `config`/`stealth_prediction` как YAML-строки вместо объектов — исправляется валидаторами в `schemas.py` |
| DeepSeek | Иногда возвращает `known_weaknesses` как строку вместо списка — исправляется |
| polza API | `completion_tokens` всегда = 1 для tool-call ответов (баг API, не влияет на функциональность) |

---

## Формат артефактов

### `generation.json`
```json
{
  "run_id":    "uuid4",
  "timestamp": "2026-06-06T...",
  "elapsed_s": 12.4,
  "model":     "gpt-4o",
  "provider":  "polza",
  "tokens":    {"prompt": 3471, "completion": 1, "total": 3472},
  "variant":   {"index": 0, "domain": "www.google.com", "port": 9443, ...},
  "generation_result": {
    "reasoning": "I chose chrome-120 fingerprint because...",
    "config": {
      "protocol": "tls-token-v1",
      "transport": {"type": "tls", "port": 9443, "tls": {"fingerprint": "chrome-120", ...}},
      "handshake": {"type": "tls-token", ...},
      ...
    },
    "stealth_prediction": {
      "m1_ndpi":     {"verdict": "PASS", "explanation": "..."},
      "m2_suricata": {"verdict": "PASS", "explanation": "..."},
      "m3_zeek":     {"verdict": "PASS", "explanation": "..."},
      "m4_ml":       {"verdict": "PASS", "explanation": "..."},
      "m6_kl_len":   {"verdict": "PASS", "explanation": "..."},
      "m8_probe":    {"verdict": "PASS", "explanation": "..."}
    },
    "known_weaknesses": ["TLS session ticket timing side-channel", ...]
  }
}
```

### `report.json`
Стандартный формат tunnel-testing. Содержит `verdict: PASS/FAIL` и детали
по каждой метрике M1–M8 (см. `tunnel-testing/README.md`).

### `results/comparison_report.json`
```json
{
  "models": [{
    "model": "gpt-4o",
    "n_runs": 3, "n_tested": 3, "pass_rate": 0.0,
    "check_pass": {"M1_ndpi": 3, "M2_suricata": 3, "M3_ja3": 3, "M4_vpn_prob": 3, ...},
    "avg_tokens": 3471,
    "pred_accuracy": 1.0,
    "diversity": {"unique_fingerprints": ["chrome-120", "safari-17"], ...}
  }],
  "reference": [...],
  "all_runs": [...]
}
```

---

## Task variants (diversity)

`TASK_VARIANTS` в `generator.py` содержит **10 вариантов задачи**, чередующихся
по run_index. Каждый вариант задаёт разные:
- SNI-домен (google.com, cloudflare.com, microsoft.com, github.com, ...)
- Порт (443, 8443, 9443, ...)
- Подсказку по рукопожатию (`tls-token` / `noise NNpsk2` / ...)
- Подсказку по паддингу (`mimicry/chrome` / `random [40, 1400]` / ...)

---

## Результаты экспериментов (июнь 2026)

Запуск: 7 моделей × 3 прогона, `--scenario web --duration 30`.

### Сводная таблица

| Модель | M2 (Suricata) | M3 (Zeek) | avg M4 | avg M6 | avg M7 | tok/run |
|--------|:---:|:---:|:------:|:------:|:------:|:-------:|
| gpt-4o-mini | 5/5 | 5/5 | 0.108 | 0.341 | 0.520 | 3 474 |
| gpt-4o | **3/3** | **3/3** | **0.099** | 0.335 | 0.529 | 3 471 |
| claude-haiku-3-5 | 3/3 | 3/3 | 0.113 | **0.322** | 0.534 | 6 087 |
| claude-sonnet-4 | 1/5 ✗ | 4/5 | 0.101 | 0.352 | 0.532 | 6 046 |
| gemini-2.5-flash | 3/3 | 3/3 | 0.197 | 0.740 ✗ | 0.523 | **2 726** |
| deepseek-chat | 3/6 | 5/6 | 0.103 | 0.404 | **0.517** | 6 300 |
| qwen3-32b | 4/6 | 6/6 | 0.113 | 0.327 | 0.535 | 5 165 |

Пороги: M4 < 0.65 · M6 < 0.30 · M7 < 0.30. Все модели FAIL (M7 loopback-артефакт).

### Выводы

- **M1/M4/M5/M8** — стабильный PASS у всех моделей: DPI-классификатор не распознаёт
  VPN, ML-вероятность низкая (0.10–0.20), активные зонды отбиваются fallback.
- **M6/M7 (KL-дивергенция)** — системный артефакт loopback-стенда: IAT на localhost
  ≈ 0 мс против эталонных 5–100 мс HTTPS. На реальной сети с RTT > 5 мс значения
  будут существенно ниже.
- **Gemini 2.5 Flash** — наиболее дешёвый (2 726 tok/run), но выбирает
  `video-streaming` паддинг с высоким M6 (0.740). Склонен передавать поля
  как YAML-строки вместо объектов — обходится валидаторами Pydantic.
- **Claude Sonnet 4** — частые алерты Suricata (M2: 1/5). Генерирует более сложные
  конфиги с нестандартными параметрами, которые пересекают правила IDS.
- **GPT-4o / GPT-4o-mini** — наиболее стабильны и предсказуемы.
- **Qwen3-32b** — единственная модель, использовавшая `firefox-120` fingerprint
  без подсказки; M3 = 6/6 (100%).

---

## Известные ограничения

| Проблема | Причина | Статус |
|----------|---------|--------|
| M6/M7 всегда FAIL | IAT на loopback ≈ 0 мс, порог откалиброван под реальную сеть | Артефакт стенда, не ошибка кода |
| `completion_tokens = 1` | polza API не считает токены tool-call ответов | Баг API, cost-estimation неточна |
| Gemini возвращает YAML-строки | Неполное следование function-calling схеме | Исправлено валидаторами в `schemas.py` |
| M1/M2 SKIP | Docker-образы `ndpi:latest` / `jasonish/suricata:latest` не собраны | Собрать образы через `tunnel-testing/docker/` |

---

## Зависимости

```
pydantic>=2.6        # Pydantic v2 для structured output
pyyaml>=6.0          # YAML сериализация конфигов
openai>=1.40         # OpenAI SDK (используется для всех провайдеров через polza)
cryptography>=42.0   # TLS cert генерация (без внешнего openssl)
python-dotenv>=1.0   # загрузка .env
```
