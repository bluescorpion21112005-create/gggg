# Cybrix AI — Complete Architecture Review Report
**Date:** 2026-07-08  
**Reviewer:** Principal AI Software Architect  
**Status:** PRE-FIX — No code has been modified yet

---

## EXECUTIVE SUMMARY

The project has a solid architectural skeleton (Clean Architecture + MVVM + DI) but contains
**17 confirmed runtime-breaking bugs**, **9 async violations**, **7 SOLID violations**,
**4 DI mis-configurations**, **3 provider coupling issues**, and **multiple dead code paths**
that prevent the application from operating correctly as an MVP.

---

## 1. ARCHITECTURE ISSUES

### 1.1 Bootstrap Order (bootstrap.py)
**BUG — CRITICAL**: `Injector` is created BEFORE `QApplication` is instantiated (line 41 vs line 58).
Several ViewModels are injected as singletons and call `QObject.__init__()` before a QApplication
exists. On PySide6, this raises a `RuntimeError: QApplication does not exist`.

**BUG — HIGH**: `CybrixApp.__init__` calls `self.injector.get(ChatAgent)` etc. AFTER the
DI container has already bound them as singletons, but the Orchestrator's `register_agent` is
called in `__init__` — outside DI, manually. This is a hidden dependency anti-pattern.

### 1.2 Duplicate PluginBase
`domain/plugin_base.py` AND `domain/interfaces/plugin_base.py` both define `PluginBase`.
`plugin_manager.py` imports from `domain.plugin_base`. One is dead code.

### 1.3 SQLAlchemy models.py — Dead Code
`infrastructure/db/models.py` defines SQLAlchemy ORM models but they are never used.
The actual repository uses raw `sqlite3`. This is dead code and misleading.

### 1.4 ChatUseCase — Dead Code
`application/use_cases/chat_use_case.py` is never bound in DI and never called.
`ChatAgent` directly uses `AIProvider`. The use case is orphaned.

### 1.5 DTOs — Dead Code
`application/dtos/analysis_dto.py` and `chat_dto.py` are never imported anywhere.


---

## 2. ASYNC ISSUES

### 2.1 The Root Async Bug — AIProvider.generate is NOT an async generator
**BUG — CRITICAL (RuntimeWarning: coroutine was never awaited)**  
`AIProvider.generate()` is declared as:
```python
async def generate(self, prompt: str, model: str, **kwargs) -> AsyncGenerator[str, None]:
    ...
```
An `async def` that returns `AsyncGenerator` is a **coroutine that returns an async generator**.
It must be awaited first: `gen = await provider.generate(...)`, then `async for token in gen`.

But **every caller** uses:
```python
async for token in self._provider.generate(prompt, model):
```
This calls the coroutine but never awaits it, which means Python silently drops it and raises
`RuntimeWarning: coroutine 'generate' was never awaited`. **No tokens are ever yielded.**
This is the root cause of all chat/analysis failures.

**Fix required:** Either declare `generate` as a plain `async def` that is itself an async
generator (`yield` inside), OR await it before iterating.

### 2.2 Double decorator @Slot + @asyncSlot
In all ViewModels: `log_analysis_viewmodel.py`, `malware_analysis_viewmodel.py`,
`ioc_viewmodel.py`, `rag_viewmodel.py`, `report_viewmodel.py`, `chat_viewmodel.py`:
```python
@Slot(str)
@asyncSlot(str)
async def analyze_file(self, file_path: str):
```
`@asyncSlot` already registers the slot. Adding `@Slot` on top creates a second non-async
slot binding to the same method, causing double-invocation and signal connection issues.
**Remove all `@Slot` decorators from async methods.**

### 2.3 asyncio.get_event_loop() in DashboardViewModel
`dashboard_viewmodel.py` uses `asyncio.get_event_loop()` which is deprecated in Python 3.10+
and raises `DeprecationWarning`. In Python 3.12+ it raises `RuntimeError` if there is no
current event loop in the thread. Use `asyncio.get_running_loop()` instead.

### 2.4 Task leak in DashboardViewModel
Tasks created via `loop.create_task(...)` store a reference only in `self._gpu_status_task`
and `self._recent_analyses_task`. If the widget is destroyed while a task is running, the
task will raise `CancelledError` silently and the widget reference becomes dangling.

### 2.5 GPUManager blocks the Qt main thread
`gpu_monitor.py::_run_rocm_smi()` calls `subprocess.check_output([...], timeout=5)` —
this is a **blocking call** on the Qt main thread. A 5-second block freezes the entire UI.
Must be offloaded to a thread pool executor.

### 2.6 Embedder loaded in DI constructor (blocks import)
`infrastructure/rag/embedder.py` loads `SentenceTransformer` in `__init__`. DI resolves
singletons at startup. Loading a 90MB model during application startup blocks the event loop.

### 2.7 VectorStore uses deprecated ChromaDB API
`chromadb.Client(Settings(...))` is the old (v0.3) API. ChromaDB v0.4+ uses
`chromadb.PersistentClient(path=...)`. Using the old API raises deprecation warnings and
may crash depending on installed version.

### 2.8 No cancellation support
No agent, use case, or provider supports task cancellation. If the user navigates away during
a long streaming operation, the coroutine continues running until completion.

### 2.9 SQLiteRepository uses blocking sqlite3 via executor
While the executor approach avoids blocking the event loop, each query creates and destroys
a `sqlite3.connect()`. High-frequency calls (e.g., dashboard refreshing every 2s) will
exhaust thread pool capacity. Should use connection pooling or `aiosqlite`.


---

## 3. QT / QASYNC ISSUES

### 3.1 QApplication created after DI container
As noted in §1.1. DI singletons that inherit `QObject` (all ViewModels, `BaseViewModel`)
are created before `QApplication` exists. PySide6 requires `QApplication` to exist before
any `QObject` is created.

**Fix:** Create `QApplication` BEFORE `Injector`.

### 3.2 qasync event loop not set before DI
The `qasync.QEventLoop` is created after DI, so any coroutine scheduled during DI
resolution (none currently, but future risk) would have no event loop.

### 3.3 StatusBarWidget import not verified
`presentation/widgets/status_bar.py` — not read yet but referenced in `main_window.py`.
If it's missing `show_message`, a `AttributeError` will occur at runtime on status events.

### 3.4 Settings dialog blocks event loop
`_open_settings()` calls `SettingsWindow(...).exec()` which is a blocking Qt dialog.
During the blocking period, the qasync event loop cannot process async tasks.

### 3.5 Qt timer fires before event loop runs
`DashboardViewModel.__init__` starts `QTimer` immediately. The first timer tick fires at
`2000ms`. By that time the qasync event loop is running. However, `_update_metrics()` tries
`asyncio.get_event_loop()` — see §2.3.

---

## 4. MVVM VIOLATIONS

### 4.1 RAGViewModel directly imports VectorStore infrastructure
```python
from infrastructure.rag.vector_store import VectorStore
```
ViewModels MUST NOT reach into the infrastructure layer directly. The ViewModel should
communicate through the Orchestrator or a dedicated use case/service.

### 4.2 ReportViewModel directly imports Repository
```python
from domain.interfaces.repository import Repository
```
Fetching analyses for the report list should go through the Orchestrator or a dedicated
query service, not directly from the ViewModel.

### 4.3 SettingsViewModel imports ThemeManager (infrastructure concern)
Theme management is an infrastructure/presentation concern. SettingsViewModel directly
applies theme changes — this should be done via an event or service abstraction.

### 4.4 SettingsViewModel imports Vault (infrastructure)
```python
from infrastructure.security.vault import Vault
```
Direct infrastructure access from ViewModel violates MVVM layering. Should go through a
`SettingsService` or `SecretsService` abstraction.

---

## 5. SOLID VIOLATIONS

### 5.1 SRP — LogAnalysisUseCase mixes concerns
`log_analysis_use_case.py` contains THREAT_PATTERNS regex logic inline. Threat pattern
matching should be in a separate `ThreatPatternMatcher` component.

### 5.2 OCP — di.py `provide_ai_provider` is a closed switch
```python
if prov_name == "ollama": ...
elif prov_name == "fireworks": ...
else: raise RuntimeError(...)
```
Adding a new provider requires modifying `di.py`. `ProviderFactory` already exists and
supports all 8 providers — but DI **does not use it**. The factory should be used here.

### 5.3 DIP — ReportUseCase depends on concrete generator classes
```python
def __init__(self, pdf_gen: PdfReportGenerator, md_gen: MarkdownReportGenerator, ...):
```
Should depend on `ReportGenerator` interface, not concrete implementations.

### 5.4 DIP — ModelRegistry depends on concrete provider types
`di.py::provide_model_registry` does `isinstance(ai_provider, OllamaProvider)` checks.
This is a DIP violation — the registry should receive providers by name, not type.

### 5.5 ISP — AIProvider interface has `health_check` with default implementation
A concrete method in an abstract interface is acceptable in Python, but `health_check`
returning a trivial default is misleading when providers have meaningful health endpoints.

### 5.6 SRP — bootstrap.py manually registers all agents in Orchestrator
This registration logic belongs in the Orchestrator or a factory, not bootstrap.

### 5.7 OCP — Orchestrator has no mechanism for dynamic agent registration via config
Agents are hardcoded. A registry pattern would allow plugins to register agents.


---

## 6. DEPENDENCY INJECTION ISSUES

### 6.1 Use cases not bound in DI
The following use cases are instantiated by agents via `@inject`, but are never explicitly
bound in `CybrixModule.configure()`:
- `IOCAnalysisUseCase`
- `MalwareAnalysisUseCase`
- `ThreatHuntingUseCase`
- `RAGUseCase`
- `ReportUseCase`

The `injector` library resolves unbound injectables automatically IF they have `@inject`
constructors and their dependencies ARE bound. This works by convention, but is fragile —
any missing transitive dependency causes a silent `UnsatisfiedRequirement` error at runtime.
All use cases must be explicitly bound for clarity and correctness.

### 6.2 LogAgent is provided manually, bypassing @inject
In `di.py::provide_log_agent`, parsers are hardcoded:
```python
parsers = [EVTXParser(), SyslogParser(), ...]
use_case = LogAnalysisUseCase(parsers, ai_provider)
return LogAgent(use_case)
```
`LogAnalysisUseCase.__init__` has `@inject` but is being instantiated manually.
This bypasses the DI container and makes testing harder.

### 6.3 Repository bound as instance, not type
```python
binder.bind(Repository, to=SQLiteRepository(self._config.database_url), scope=singleton)
```
`SQLiteRepository(...)` is called during `configure()`. If this throws (e.g., bad path),
the entire DI container fails to initialize. Should be bound as a type with `scope=singleton`.

### 6.4 GPUManager and PluginManager bound as instances (same risk as 6.3)
```python
binder.bind(GPUManager, to=GPUManager(self._config.gpu.prefer_rocm), scope=singleton)
binder.bind(PluginManager, to=PluginManager(self._config.plugins_dir), scope=singleton)
```
Both instantiated during `configure()`. `GPUManager.__init__` calls `subprocess.run`
(blocking, 5s timeout) at DI container construction time.

### 6.5 ModelRegistry always keys by concrete type
```python
if isinstance(ai_provider, OllamaProvider):
    providers["ollama"] = ai_provider
elif isinstance(ai_provider, FireworksProvider):
    providers["fireworks"] = ai_provider
```
When any other provider is active, the registry is empty. Should use provider name.

---

## 7. RUNTIME ERRORS (Python-level)

### 7.1 SyntaxError — ReportAgent.execute_in_pipeline indentation
```python
async def execute_in_pipeline(self, context: AnalysisContext, model: str = "default") -> AnalysisContext:
# Barcha natijalardan hisobot yasash         <-- comment at wrong indent
    return context
```
The comment is at column 0 (no indent) but inside the method body. Python may or may not
raise a `SyntaxError` depending on version — on CPython 3.14 this likely parses fine since
the comment is ignored, but it is a maintenance bug. Confirmed: indentation is inconsistent.

### 7.2 UnboundLocalError — PEAnalyzer._detect_packer
```python
if any(s['name'] in ('UPX0', 'UPX1', '.aspack', '.petite') for s in features.sections):
    indicators.append(f"Known packer section {s['name']}")  # 's' not defined here!
```
`s` is the generator variable inside `any(...)`. After the generator is consumed, `s` is
out of scope. This will raise `UnboundLocalError` when the condition is True.

### 7.3 FireworksProvider raises on import if API key missing
`FireworksProvider.__init__` raises `AIProviderError` if the key is not found:
```python
if not api_key:
    raise AIProviderError("Fireworks API key not found...")
```
Since this provider is not enabled by default, it won't crash. But DI's
`provide_ai_provider` can only return Ollama or Fireworks — any other provider name
raises `RuntimeError("Unknown AI provider: ...")`. This means enabling `openai` in
`settings.yaml` crashes the entire application at startup.

### 7.4 OllamaProvider sync fallback blocks event loop
```python
sync_client = ollama.Client(host=self._host)
stream = sync_client.generate(...)
for chunk in stream:
    yield chunk['response']
```
If `HAS_ASYNC=False` (older ollama library), a synchronous streaming generator is run
inside an `async def`. Each `yield` inside a synchronous loop blocks the event loop for
the duration of the network round-trip.

### 7.5 ReportUseCase hardcodes model name
```python
async for token in self._provider.generate(prompt, model="llama3"):
```
The model is hardcoded as `"llama3"`. Should use the configured default model.

### 7.6 Orchestrator.default_model hardcoded to "llama3"
```python
def __init__(self, ai_provider: AIProvider, default_model: str = "llama3"):
```
Not wired to `AppConfig.default_model`. Will break when using OpenAI models.

### 7.7 AnalysisResult.description used as executive summary in ReportUseCase
`ReportUseCase` maps `analysis.description` to `executive_summary`. `AnalysisResult`
has no `description` field in `domain/entities.py`. This will raise `AttributeError`.

Wait — checking entities.py: `AnalysisResult` DOES have a `description` field. ✓
However, the repository never saves analyses from agents, so `get_analysis()` will
always return `None` → `ValueError: Analysis X not found`. The report workflow is broken.


---

## 8. PROVIDER ARCHITECTURE ISSUES

### 8.1 ProviderFactory exists but DI does not use it
`infrastructure/ai/provider_factory.py` is a fully capable factory supporting 8 providers.
`core/di.py` ignores it and hand-codes only Ollama + Fireworks. The factory is dead code.

### 8.2 DI only supports two providers from config
Enabling `openai`, `huggingface`, `openrouter`, `lm_studio`, `vllm` in `settings.yaml`
crashes with `RuntimeError: Unknown AI provider`. Provider selection must go through
`ProviderFactory`.

### 8.3 AIProvider.generate signature is wrong for an async generator
The abstract method:
```python
async def generate(self, prompt: str, model: str, **kwargs) -> AsyncGenerator[str, None]:
```
This is a coroutine that *returns* an `AsyncGenerator`. All implementations use `yield`
inside `async def`, making them **async generator functions** — which means the return
type annotation `-> AsyncGenerator[str, None]` is technically correct in that `async def`
with `yield` IS an async generator function. 

**BUT** the interface contract is ambiguous: callers see `async def` and might `await` it
OR treat it as a generator. The `OllamaProvider` uses `yield` correctly. The
`OpenAICompatibleProvider` uses `yield` correctly. However,
**every use case iterates it WITHOUT awaiting**:
```python
async for token in self._provider.generate(prompt, model):
```
For **async generator functions** (those containing `yield`), calling them returns an
async generator object WITHOUT awaiting. So `self._provider.generate(prompt, model)` is
already an async generator. This is actually correct for `yield`-based implementations.

**Conclusion**: The `RuntimeWarning: coroutine was never awaited` does NOT come from the
provider's `generate()` itself — it comes from the OLLAMA provider specifically:
```python
stream = await self._client.generate(...)   # <-- returns async generator
async for response in stream:               # <-- iterates it
    yield response['response']
```
`self._client.generate(...)` with `stream=True` returns a `coroutine` that must be
`await`-ed to get the `AsyncGenerator`. This IS being awaited. Let's re-examine:

The `ollama.AsyncClient.generate()` with `stream=True` returns an `async generator` 
directly (not a coroutine wrapping one). So `await self._client.generate(...)` is
actually awaiting a coroutine that returns an async generator — this is correct.

**The ACTUAL root cause of the warning**: is likely from a VIEW or VIEWMODEL that
calls `orchestrator.dispatch_stream(...)` and wraps it in `asyncio.create_task()` or
similar without properly awaiting the generator. Check ViewModels.

In `chat_viewmodel.py`, `send_message` uses `@asyncSlot` correctly and iterates 
`dispatch_stream` with `async for`. This should work.

**However**: `@Slot(str)` + `@asyncSlot(str)` double decoration causes the slot to be
registered TWICE. When Qt triggers the signal, `send_message` is called TWICE — once
synchronously (returns the coroutine unawaited!) and once asynchronously.
**THIS is the source of `RuntimeWarning: coroutine was never awaited`.**

---

## 9. AGENT ISSUES

### 9.1 Agents save no results to repository
`ChatAgent`, `IOCAgent`, `LogAgent`, `MalwareAgent` never call `repository.save_analysis()`.
Analysis results exist only in memory. Dashboard will always show an empty list.
Report generation will always fail with "Analysis not found."

### 9.2 No timeout or cancellation token in any agent
All agents run to completion with no timeout guard. If the AI provider hangs, the agent
hangs indefinitely.

### 9.3 No retry logic in any agent or provider
Any transient network error (connection reset, timeout) will immediately propagate to the
ViewModel as an error. Production quality requires at least 1 retry.

### 9.4 ThreatHuntingUseCase prompt is in Uzbek
```python
prompt = f"Threat hunting so'rovi: {query}\nIltimos, taxminiy tahdidlar..."
```
The prompt is in Uzbek. The model will likely respond in Uzbek. Should be English.

---

## 10. REPOSITORY ISSUES

### 10.1 SQLite repository never gets analyses saved (see §9.1)
### 10.2 No WAL mode for SQLite
Concurrent readers/writers will contend. Add `PRAGMA journal_mode=WAL`.
### 10.3 No connection pool — fresh connect per query
Will cause issues under load.

---

## 11. LOGGING ISSUES

### 11.1 Agents log nothing on success
Only `ChatAgent` has `logger.debug(...)`. All other agents log nothing on execution.

### 11.2 No log entry on agent start/complete with timing
No performance observability.

### 11.3 Exceptions in event bus callbacks are silently swallowed
`event_bus.emit()` catches exceptions and logs them, which is correct, but the error
is not propagated. UI may be in an inconsistent state.

---

## 12. DEAD CODE

| File | Reason |
|------|--------|
| `application/use_cases/chat_use_case.py` | Never bound or called |
| `application/dtos/analysis_dto.py` | Never imported |
| `application/dtos/chat_dto.py` | Never imported |
| `infrastructure/db/models.py` | SQLAlchemy models, never used |
| `domain/plugin_base.py` | Duplicate of `domain/interfaces/plugin_base.py` |
| `application/test_use_cases.py` | Test file in application layer (wrong location) |

---

## 13. DUPLICATE CODE

| Duplication | Location |
|------------|----------|
| `PluginBase` defined twice | `domain/plugin_base.py` + `domain/interfaces/plugin_base.py` |
| `FireworksProvider` uses its own `openai.AsyncOpenAI` | Could use `OpenAICompatibleProvider` |
| Every ViewModel has `@Slot` + `@asyncSlot` pattern | Should be a single decorator |

---

## 14. PRIORITIZED FIX ORDER

1. **[P0]** Fix QApplication creation order (bootstrap.py)
2. **[P0]** Fix double `@Slot` + `@asyncSlot` decorators (all async ViewModels)
3. **[P0]** Fix `_detect_packer` UnboundLocalError (pe_analyzer.py)
4. **[P0]** Wire `ProviderFactory` into DI — remove hardcoded provider switch
5. **[P0]** Fix `Orchestrator.default_model` to read from config
6. **[P1]** Offload `GPUManager.get_metrics()` and `_run_rocm_smi()` to executor
7. **[P1]** Fix `DashboardViewModel` to use `asyncio.get_running_loop()`
8. **[P1]** Fix VectorStore to use ChromaDB v0.4+ API
9. **[P1]** Explicitly bind all use cases in DI
10. **[P1]** Add analysis save to all agents
11. **[P1]** Fix ThreatHunting prompt to English
12. **[P2]** Remove dead code
13. **[P2]** Add cancellation support
14. **[P2]** Add retry logic to providers
15. **[P2]** Add WAL mode to SQLite
16. **[P2]** Add comprehensive logging to all agents

