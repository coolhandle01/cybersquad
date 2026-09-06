# Project template overrides

Spec Kit resolves a template `<name>` from this `overrides/` layer first
(highest priority, "replace"), then presets, then extensions, then the core
`.specify/templates/`. See `.specify/scripts/bash/common.sh` (`resolve_template_content`).

Names must match `[a-z0-9-]+` (hyphens, not underscores).

## Templates here

| Template | Resolve as | Use for |
|---|---|---|
| `spec-template` | `spec-template` | Generic (non-tool) features. Core template, with the Functional Requirements section rewritten in EARS with the `SHALL` modal (see the constitution). |
| `cyber-tool` | `cyber-tool` | Specifying a `@cyber_tool` (a CrewAI tool a squad agent invokes). |
| `pentest-tool` | `pentest-tool` | Specifying a pentest probe (`check_X` behind `@pentest_tool`, returning `list[RawFinding]`). Extends the cyber-tool contract. |

## Where specs live

Feature specs are generated under `docs/design/<slug>/` (this repo's design-doc
home), not the upstream default `specs/<NNN>-<slug>/`. `create-new-feature.sh`
is pointed there and names the directory by the bare slug (no numeric prefix).
Spec Kit v1.0.4 exposes no config knob for the specs root, so this is a small
edit to the vendored script - re-apply it after any `specify` upgrade.

## Seeding a tool feature from one of these

`/speckit-specify` seeds `spec.md` from the core `spec-template`. To base a tool
feature on a tool template instead, resolve it into the feature's `spec.md` after
the feature directory exists:

```sh
.specify/scripts/bash/resolve-template.sh pentest-tool > docs/design/<slug>/spec.md
```

then fill in every `[PLACEHOLDER]` and resolve each `[NEEDS CLARIFICATION: ...]`.
