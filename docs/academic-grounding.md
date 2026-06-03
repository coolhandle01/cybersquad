# Academic grounding

Some of cybersquad's structural decisions cite a specific upstream work
at the assertion site - a docstring, a comment, a model name. This file
is the longer-form companion: what each one is, what is actually in it,
how it maps to the pipeline.

Covers the OWASP Open Asset Model (the graph shape cybersquad emits
into, when amass lands per #45) and the academic papers that ground
the `AttackGraph` / `AttackTree` / `AttackForest` naming in
`models/attack/` and `models/asset/`.

cybersquad's design favours open-source, community-maintained tooling
and standardised vocabularies (notably OWASP Amass, the OWASP Top 10,
and the OWASP Cheat Sheet Series) over reimplementations of the
academic work cited below. The papers are cited for the intellectual
grounding they provide, not as implementation references.

## OWASP Open Asset Model (the graph cybersquad emits into)

OWASP Amass's Open Asset Model (OAM):
<https://github.com/owasp-amass/open-asset-model>

OAM is a typed graph model of attack-surface assets. Three things
matter for cybersquad's design:

- **Assets are typed nodes.** FQDN, IPAddress, AutonomousSystem,
  Netblock, RIROrganization, TLSCertificate, ContactRecord, Service,
  among others defined by the spec. Each asset type has its own
  schema; not all asset types carry the same properties.
- **Relations are typed edges.** Edges carry semantic types rather
  than being untyped pointers - for example:
  `FQDN -A_RECORD-> IPAddress`, `IPAddress -CONTAINED_BY-> Netblock`,
  `Netblock -ANNOUNCED_BY-> AutonomousSystem`,
  `AutonomousSystem -MANAGED_BY-> RIROrganization`. Queries can
  pattern-match on edge type.
- **Properties hang off assets** to add metadata: `DNSRecordProperty`
  (DNS data), `SimpleProperty` (arbitrary k/v), `SourceProperty` (which
  tool / source produced the fact), `VulnProperty` (CVE-style
  vulnerability data). Provenance is in the model.

This is what makes amass a graph database rather than a property bag.
You can ask "which IPAddresses sit in Netblock N?" or "which FQDNs
resolve to IPs in ASN X?" and the model has the shape to answer.

### How cybersquad uses it

The typed shapes in the `models/asset/` package (one module per OAM
asset family) are designed to round-trip into OAM:

- The `FQDN` / `IpAddr` primitives validate the identifiers OAM assets
  are keyed on. The OAM `IPAddress` *asset* lives in
  `models/asset/network.py`; the `IpAddr` primitive that validates an IP
  literal lives in `models/primitives/ip_addr.py` (the primitive yields
  the `IPAddress` name to the asset).
- `AutonomousSystem` / `Netblock` carry the ASN and announced-prefix
  assets (the legacy `AsnRecord` shape feeds them).
- `Organization` plus its `ContactRecord` records carry the RIR
  registrant data (RDAP).
- `IpEnrichment` composes one IP's ASN / RDAP / PTR facets into a single
  cybersquad-native subgraph bundle.

When #45 lands, the OSINT Analyst writes these records into the OAM
graph (Postgres-backed). Downstream agents query the graph for context
per decision.

A canonical link to the OWASP Amass team's design essays on OAM is
pending; the spec repository linked above is the authoritative
reference for the model itself.

## Schneier 1999 - attack trees

Bruce Schneier, *Attack Trees*, Dr. Dobb's Journal, December 1999.
<https://www.schneier.com/academic/archives/1999/12/attack_trees.html>

The original formalism. A goal at the root, AND/OR sub-goals as children,
leaves as atomic attack steps. Probabilities or costs hang off each leaf;
the tree as a whole answers "what is the lowest-cost or most likely
path to this goal?" by rolling values up.

Two important properties:

- **Forward-looking.** You start from a goal you want to achieve and
  decompose it. The tree is a *thinking tool*, typically hand-drawn,
  authored against intent.
- **Per-goal, not per-system.** One tree, one goal. A different objective
  is a different tree.

In cybersquad this maps to the **VR's worldview**. Per probe + target the
Vulnerability Researcher is asking "what would success look like and what
are the sub-conditions for it" - that decomposition is a Schneier tree.
The `AttackTree` shape in `models/attack/tree.py` is intentionally degenerate
today (no `children`, no `decomposition: Literal["AND", "OR"]`) but the
naming reserves the room for a recursive shape later without renaming.

## Sheyner et al. 2002 - automated attack-graph generation and MDP analysis

Oleg Sheyner, Joshua Haines, Somesh Jha, Richard Lippmann, Jeannette M. Wing,
*Automated Generation and Analysis of Attack Graphs*, IEEE Symposium on
Security and Privacy 2002. DOI [10.1109/SECPRI.2002.1004377](https://doi.org/10.1109/SECPRI.2002.1004377).

Where Schneier draws trees by hand, Sheyner *generates a graph mechanically*.
Nodes are system states (which hosts have what privileges, which services
are reachable, what trust exists). Edges are atomic attacks - single
exploits that, when applied, transition the state. A path from an initial
state to a goal state is one attack scenario; the set of all such paths is
the attack graph.

**How they generated it.** Encode the network as state variables, the
exploits as a transition relation, the attacker goal as a property. Run a
symbolic model checker (they used NuSMV) and ask "find a counterexample
to 'goal is unreachable'." The standard model-checker returns one
counterexample; they extended it to return *all* paths, with cycles
handled. The output is the graph.

**Analyses on the graph.** Two are immediately useful:

- **Probabilistic / MDP.** Each edge has a probability of success, each
  goal has a value, so attack-graph reasoning frames cleanly as a Markov
  Decision Process. You can compute expected utility of a scenario and
  reason about *which path to try first* under uncertainty. The paper's
  own caveat is that the full MDP is intractable at scale (state
  explosion is the dominant scaling limitation of model-checked attack
  graphs); in practice one approximates with A\* and a domain heuristic.
- **Minimum-cut.** What is the smallest set of edges that would need to
  be removed to break every path to the goal? The defender's "minimum
  patch set" question. NP-hard but admits tractable approximation
  algorithms.

In cybersquad this maps to the **PT's worldview**. Given the trees the VR
produced, plan a search that maximises expected value of finding bugs -
Sheyner-style MDP reasoning, A\* + domain heuristic in practice. The
`AttackForest` docstring in `models/attack/forest.py` cites Sheyner
specifically for this MDP framing.

## Related work: Ou et al. 2005 - MulVAL

Xinming Ou, Sudhakar Govindavajhala, Andrew W. Appel, *MulVAL: A
Logic-based Network Security Analyzer*, USENIX Security 2005.
<https://www.usenix.org/legacy/event/sec05/tech/full_papers/ou/ou.pdf>

The canonical multi-host attack-graph reasoner: Datalog facts plus
XSB-Prolog tabled evaluation. cybersquad does not currently use
MulVAL. It is listed here because it is the reference any reader of
this material is likely to consult next, and because the OAM graph
cybersquad emits would be a plausible input to a MulVAL-style
reasoner should cybersquad's scope ever extend into multi-host
attack-path enumeration.

## How they stack in cybersquad

| Role | Worldview | Reference |
|---|---|---|
| OSINT Analyst | Describes the graph. Collects facts about hosts, services, technologies, trust. | OWASP Open Asset Model (amass) |
| Vulnerability Researcher | Finds the trees. Per probe + target, decomposes a sub-goal. | Schneier 1999 |
| Penetration Tester | Searches the forest. Expected-value path selection across trees. | Sheyner 2002 (MDP), A\* with a domain heuristic in practice |

Three formalisms from three traditions, each in the role its formalism is
good at. The naming in `models/attack/` (`AttackGraph`, `AttackTree`,
`AttackForest`) is meant to make the role each agent plays legible to a
contributor who knows the literature.
