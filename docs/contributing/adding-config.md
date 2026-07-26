# Adding a new config value

1. Add a field to the appropriate dataclass in `config.py` using `default_factory=lambda: os.getenv(...)`.
2. Document it in `.env.example` with a comment explaining valid values.
3. If the value is used in a tool, thread it through via `config.<section>.<field>` - do not hardcode fallback values in the tool.

## Why `default_factory=lambda`

All environment variables are read in `config.py` using `field(default_factory=lambda: ...)`. This is intentional - it means values are read at instantiation time, not at class-definition time, which lets `monkeypatch.setenv()` work correctly in tests. Do not change field defaults to bare expressions.

```python
# correct
max_programmes: int = field(default_factory=lambda: int(os.getenv("H1_MAX_PROGRAMMES", "10")))

# wrong - evaluated once at import time, monkeypatch has no effect
max_programmes: int = int(os.getenv("H1_MAX_PROGRAMMES", "10"))
```
