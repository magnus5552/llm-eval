# llm-eval — LLM Tunnel Config Generation & Testing Pipeline

Экспериментальный пайплайн для сравнительного анализа способности языковых
моделей генерировать конфигурации прокси-туннелей, устойчивых к детектированию.

## Схема работы

```
┌─────────────────────────────────────────────────────────────────┐
│  pipeline.py  run-all  --models claude-opus-4 gpt-4o deepseek  │
└──────────────┬──────────────────────────────────────────────────┘
               │
    ┌──────────▼──────────────────────────────────┐
    │  generator.py                               │
    │  ─ строит системный промпт (prompts/)       │
    │  ─ вызывает LLM с structured output         │
    │  ─ возвращает GenerationResult (Pydantic)   │
    └──────────┬──────────────────────────────────┘
               │  GenerationResult
    ┌──────────▼──────────────────────────────────┐
    │  serializer.py                              │
    │  ─ TunnelConfig → YAML                      │
    └──────────┬──────────────────────────────────┘
               │  config.yaml
    ┌──────────▼──────────────────────────────────┐
    │  evaluator.py                               │
    │  ─ генерирует TLS-сертификат (openssl)      │
    │  ─ инжектирует PSK / Noise-ключи            │
    │  ─ запускает tunnel-testing/run_test.py     │
    │  ─ возвращает M1–M8 report.json             │
    └──────────┬──────────────────────────────────┘
               │
    ┌──────────▼──────────────────────────────────┐
    │  results/{model}/{run_id}/                  │
    │    generation.json   ← structured output    │
    │    config.yaml       ← итоговый конфиг      │
    │    report.json       ← M1–M8 вердикт        │
    │  results/reference/{name}/                  │
    │    report.json       ← референсные конфиги  │
    └─────────────────────────────────────────────┘
               │
    ┌──────────▼──────────────────────────────────┐
    │  comparison.py                              │
    │  ─ таблицы pass-rate по моделям             │
    │  ─ точность предсказаний LLM                │
    │  ─ сравнение с референсами                  │
    │  ─ comparison_report.json                   │
    └─────────────────────────────────────────────┘
```

## Структура файлов

```
llm-eval/
├── requirements.txt
├── pipeline.py       # CLI: generate / reference / run-all / models
├── comparison.py     # анализ и таблицы
├── schemas.py        # Pydantic: TunnelConfig + GenerationResult (structured output)
├── providers.py      # LLM-провайдеры: Anthropic, OpenAI-compat
├── generator.py      # построение промптов + вызов LLM
├── evaluator.py      # подготовка конфига + запуск tunnel-testing
├── serializer.py     # TunnelConfig → YAML
└── prompts/
    ├── system.md     # системный промпт (описание DSL + метрики + few-shot)
    └── task.md       # шаблон задачи (параметризован: домен, порт, подсказки)
```

## Быстрый старт

### 1. Установить зависимости
```bash
pip install -r requirements.txt
```

### 2. Настроить API-ключи
```bash
# .env в папке llm-eval/ (python-dotenv подхватит автоматически)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GOOGLE_API_KEY=...         # для Gemini
DEEPSEEK_API_KEY=...       # для DeepSeek
```

### 3. Сгенерировать конфиги (без тестирования — быстро)
```bash
python pipeline.py generate --model claude-opus-4 --runs 5
```

### 4. Сгенерировать и сразу тестировать
```bash
python pipeline.py generate --model claude-opus-4 --runs 5 --test --duration 30
```

### 5. Запустить все модели + референсные конфиги
```bash
python pipeline.py run-all \
  --models claude-opus-4 claude-sonnet-4 gpt-4o deepseek-chat \
  --runs 5 \
  --reference \
  --duration 30
```

### 6. Сравнительный анализ
```bash
python comparison.py
```

## Поддерживаемые модели

| Алиас | Провайдер | API-ключ |
|-------|-----------|----------|
| `claude-opus-4` | Anthropic | `ANTHROPIC_API_KEY` |
| `claude-sonnet-4` | Anthropic | `ANTHROPIC_API_KEY` |
| `claude-sonnet-3-5` | Anthropic | `ANTHROPIC_API_KEY` |
| `gpt-4o` | OpenAI | `OPENAI_API_KEY` |
| `gpt-4.1` | OpenAI | `OPENAI_API_KEY` |
| `gpt-4o-mini` | OpenAI | `OPENAI_API_KEY` |
| `gemini-2.0-flash` | Google (compat) | `GOOGLE_API_KEY` |
| `gemini-2.5-pro` | Google (compat) | `GOOGLE_API_KEY` |
| `deepseek-chat` | DeepSeek (compat) | `DEEPSEEK_API_KEY` |
| `deepseek-r1` | DeepSeek (compat) | `DEEPSEEK_API_KEY` |

## Structured output

Каждый LLM-вызов возвращает `GenerationResult` (схема Pydantic):

```python
class GenerationResult(BaseModel):
    reasoning: str            # цепочка рассуждений о выборе параметров
    config: TunnelConfig      # полная DSL-конфигурация
    stealth_prediction: StealthPrediction  # предсказание по каждой метрике
    known_weaknesses: list[str]            # известные слабые места
```

`TunnelConfig` — точное зеркало Go-структур из `tunnel-gen/dsl/schema.go`,
что гарантирует валидность сгенерированного YAML без ручной правки.

Для Anthropic используется Tools API (`tool_choice: forced`).
Для OpenAI и OpenAI-совместимых API — Function calling.

## Формат артефактов

### `generation.json` — структурированный вывод LLM
```json
{
  "run_id": "uuid4",
  "timestamp": "2025-05-26T...",
  "model": "claude-opus-4-5",
  "provider": "anthropic",
  "tokens": {"prompt": 1500, "completion": 800, "total": 2300},
  "variant": {"domain": "www.google.com", "port": 9443, ...},
  "generation_result": {
    "reasoning": "I chose firefox-120 fingerprint because...",
    "config": { ... },
    "stealth_prediction": {
      "m1_ndpi":     {"verdict": "PASS", "explanation": "..."},
      "m2_suricata": {"verdict": "PASS", "explanation": "..."},
      ...
    },
    "known_weaknesses": ["Token timing side-channel possible on slow networks", ...]
  }
}
```

### `report.json` — M1–M8 результаты tunnel-testing
Стандартный формат tunnel-testing (см. tunnel-testing/README.md).

### `results/comparison_report.json` — агрегированный отчёт
```json
{
  "models": [
    {
      "model": "claude-opus-4-5",
      "pass_rate": 0.8,
      "check_pass": {"M1_ndpi": 5, "M2_suricata": 5, ...},
      "avg_tokens": 1850,
      "pred_accuracy": 0.87,
      "diversity": {"unique_fingerprints": ["chrome-120", "firefox-120"], ...}
    }
  ],
  "reference": [...],
  "all_runs": [...]
}
```

## Параметры diversity для воспроизводимых экспериментов

`TASK_VARIANTS` в `generator.py` содержит 10 вариантов задачи:
разные SNI-домены, порты, подсказки по рукопожатию и паддингу.
При N прогонах первые N вариантов используются по кругу (cycle),
что создаёт детерминированное разнообразие.

## Связь с туннель-тестингом

Пайплайн вызывает `tunnel-testing/run_test.py` для каждого конфига.
Все восемь метрик M1–M8 (nDPI, Suricata, Zeek/энтропия, ML, KL-длины,
KL-IAT, активный зонд) вычисляются стандартным способом.
Референсные конфиги из `tunnel-gen/examples/` тестируются тем же методом,
что обеспечивает корректное сравнение LLM-генерации с ручными прототипами.
