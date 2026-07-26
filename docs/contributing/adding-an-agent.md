# Adding a new agent

1. Create `squad/<role-name>/` with:
   - `__init__.py` - `@tool` functions + `MEMBER = SquadMember(slug=..., dir=Path(__file__).parent, tools=[...])`
   - `role.md`, `goal.md`, `backstory.md` - drive the CrewAI Agent
   - `description.md`, `expected_output.md` - drive the Task
2. Import the new `MEMBER` into `_SQUAD` in `crew.py`.
3. Wire its task into `build_tasks()` in `tasks.py` with correct `context` dependencies.
4. Add unit tests covering the new tool's logic.

## Prompt-file rules

Each agent's prose lives in five single-purpose markdown files inside its package: `role.md`, `goal.md`, `backstory.md`, `description.md`, `expected_output.md`. `SquadMember.read("<name>")` loads `<name>.md` and strips whitespace. Missing files raise `FileNotFoundError` at agent/task build time. No separators, no parsing.
