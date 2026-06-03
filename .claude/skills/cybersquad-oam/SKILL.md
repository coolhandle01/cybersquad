---
name: cybersquad-oam
description: The OWASP Open Asset Model (OAM) is the vocabulary models/asset/ implements - typed asset nodes, typed relation edges, and properties hung off assets, faithful to amass field for field. cybersquad names yield to OAM names. Builds on cybersquad-models. Load before editing any file under models/asset/.
---

# cybersquad OAM

`models/asset/` is a faithful implementation of the **OWASP Open Asset Model (OAM)** - the typed graph vocabulary OWASP Amass deals in. `cybersquad-models` carries the general Pydantic-contract rules; this skill carries the OAM-specific overlay: what the shapes *mean* in OAM terms, how closely they must track upstream, and the naming rule that follows. Editing an asset / property / relation struct is editing the cybersquad-native form of an amass graph node, so the upstream model is the spec you are implementing against.

The longer-form companion - what OAM is, the assets/relations/properties triad, and how the three academic traditions (OAM / Schneier / Sheyner) map onto the OSINT Analyst / VR / PT - is `docs/academic-grounding.md`. Upstream: <https://github.com/owasp-amass/open-asset-model>, and each `models/asset/` module docstring links the specific OAM page for the type it models.

## The three OAM shapes

OAM models an attack surface as a graph of three things. `models/asset/` mirrors the split: `*.py` per asset family, `relation.py`, `property.py`.

1. **Assets are typed nodes.** `FQDN`, `IPAddress`, `Netblock`, `AutonomousSystem`, `Service`, `Product` / `ProductRelease`, `URL`, `TLSCertificate`, `ContactRecord`, ... Each has its own schema; not all carry the same fields. A cybersquad asset struct mirrors amass field for field, with the OAM json tag named in a trailing comment so the mapping is checkable (`source: str  # name`).
2. **Relations are typed edges.** `Relation` (in `relation.py`) is the flat edge record; `RelationType` is the closed `StrEnum` of edge kinds (`A_RECORD`, `CONTAINED_BY`, `port`, `product_used`, ...). Edges carry a semantic type, not an untyped pointer - the graph can pattern-match on it. A new edge kind is a new `RelationType` member, never a bare string.
3. **Properties hang off assets.** A fact about an asset is a *property attached to the node*, not a standalone asset: `VulnProperty` (a CVE/CWE annotation), `SourceProperty` (provenance), `DNSRecordProperty` (a DNS record), `SimpleProperty` (arbitrary k/v). See "Properties are annotations" below.

## Faithful to amass, field for field

The asset structs track amass deliberately closely - the point is that `models/asset/` round-trips into the OAM graph when #45 lands (amass over a Postgres-backed graph). So:

- Mirror amass's field names and shapes; name the OAM json tag in a trailing comment (`property_value: str  # property_value`).
- Link the upstream OAM page for the type in the module docstring.
- Faithfulness beats local convenience where they conflict: `Url.host` is a bare `str` (not the `FQDN` primitive) because OAM keeps it an open string that legitimately holds an IPv4/IPv6/IDN literal; `TLSCertificate.subject_alt_names` is `list[str]` (not `list[FQDN]`) because a cert's SANs include wildcards and `iPAddress` entries the FQDN validator would reject. When you relax a primitive for OAM fidelity, say why in a comment - it reads as a mistake otherwise.

## OAM names win; cybersquad code moves out of the way

**Rule of thumb: when a cybersquad name would collide with an OAM asset name, rename the cybersquad side, never the reverse.** The OAM owns `IPAddress`, `Netblock`, `Service`, `Product`, `URL`, `TLSCertificate`, ... as *asset* names. A primitive, helper, or local symbol that wants the same word yields.

Worked example (#161): the typed-string primitive for an IP literal was `IPAddress`, colliding with the OAM `IPAddress` *asset* that `models/asset/network.py` now models under that exact name. The primitive was renamed `IPAddress` -> `IpAddr` (`models/primitives/ip_addr.py`, re-exported from `models/__init__.py`); every field type and import moved with it. The distinction is load-bearing, so it is not a blanket find-replace: prose about the *primitive* says `IpAddr`, prose about the *OAM asset* keeps `IPAddress`. (`cybersquad-models` keeps a one-line pointer to this rule because it also bites when naming a primitive, which is a `models/primitives/` edit this skill does not load on.)

## Properties are annotations, additive and default-empty

A vulnerability is not a node - it is a `VulnProperty` hung off the asset that has it (`Endpoint` / `Service` / `ProductRelease` / `Url` / host `FQDN` all carry a `vulns: list[VulnProperty]`). Same for provenance (`sources: list[SourceProperty]`). Two rules fall out:

- **Additive + default-empty.** A property list defaults to `Field(default_factory=list)` so an artefact written before the property existed still `model_validate_json`s - the OAM graph grows by annotation, it does not break old shapes. Adding a property to an asset is a non-migrating change by construction.
- **Provenance is stamped at write time, by the producer.** Whoever materialises an asset stamps a `SourceProperty(source="nmap"/"dnsx"/..., confidence=...)` then and there - `tools/recon/nmap/service.py`, `ip_graph.py`, `httpx/parser.py` are the examples. Carry the real confidence / TTL the tool reported through to the property; do not synthesise it. A property the LLM never authored (a CVE from NVD) follows the prompt-injection rules in `cybersquad-models` - tool-captured external text, flagged and bounded on the *persisted* annotation.

## The on-disk asset graph

The per-host workspace store (`tools/recon_host_store.py`) is the disk form of one FQDN asset node's evidence: `assets/<fqdn>/` holds `services.json` / `product_releases.json` / `urls.json` / `relations.json` / ... - one file per OAM facet - and the run-level infrastructure assets (one IP serving many FQDNs: `AutonomousSystem` / `Netblock` / `Organization`) sit beside them at `assets/*.json`. Each `save_X` / `load_X` is the writer/reader workspace pair (`cybersquad-tool`); the JSON shapes are what #45 swaps for amass inserts.

Caveat that lives at that boundary: the host segment of those paths is **not** always a validated `FQDN` even where the signature says so - it can be derived from a `RawFinding.target` or a parsed URL host. A function annotation does not run the validator (only model construction does); `host_dir` sanitises and rejects `.` / `..` for exactly this reason. See the "annotation is not a runtime check" note in `cybersquad-tool`.

## Where the asset shapes live

One module per cohesive OAM concern under `models/asset/`; the authoritative map is the table in `models/asset/__init__.py` (this is a pointer, not a mirror). Curation shapes that are *not* OAM assets live outside the package on purpose: the OA's `HostInsight` / `HostScore` / `HostRole` / `OpenPortsMap` in `models.insight`, and the `AttackGraph` bundle (with `AttackTree` / `AttackForest`) in `models.attack`. If a shape is not an amass asset type, it does not belong in `models/asset/`.

## Connection to other skills

- **`cybersquad-models`**: the general Pydantic contract - typed primitives, prompt-injection rules, the writer/reader coupling. This skill is the OAM specialist that stacks on it.
- **`cybersquad-tool`**: the writer/reader workspace pair, and the "annotation is not a runtime check" trap the `assets/<fqdn>/` path sink depends on.
- **`docs/academic-grounding.md`**: the longer-form OAM explainer plus the Schneier / Sheyner grounding for `AttackTree` / `AttackForest`.
