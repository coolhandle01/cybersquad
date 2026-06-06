# Adding a new tool

Tools are `@tool`-decorated functions in a wrapper module under `squad/<agent>/tools/` (shared wrappers live under `squad/tools/`); the agent's `squad/<agent>/__init__.py` imports each wrapper, assembles `MEMBER.tools`, and re-exports it. The docstring is the agent's only guidance for when and how to call the tool - write it as an instruction, not a description.

One concern per tool. The PT agent selects tools based on nmap evidence and detected technologies; bundling unrelated checks removes that selectivity.

Tests must mock all network and binary calls. Patch `socket.create_connection` at the module path where it is imported (e.g. `tools.cloud.databases.redis.socket.create_connection`), not at the top-level `socket` module.

## Probe enumerations

When a tool iterates over a fixed set of attack vectors (headers, payloads, error markers, URI paths), define them as a `StrEnum` in the tool module rather than a bare list or tuple. This makes the set inspectable, importable in tests, and self-documenting:

```python
# correct
from enum import StrEnum

class XSSHeader(StrEnum):
    USER_AGENT = "User-Agent"
    REFERER = "Referer"
    X_FORWARDED_FOR = "X-Forwarded-For"

for header in XSSHeader:
    ...

# wrong - opaque list, not reusable in tests
_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For"]
```

Tests should import the enum and assert against `set(MyEnum)` rather than duplicating the string literals.
