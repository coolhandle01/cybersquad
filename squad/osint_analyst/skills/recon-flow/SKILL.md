---
name: recon-flow
description: How the OSINT Analyst works the surface after the initial sweep - sweep first, then pivot with judgement using Lookup IP Assets, Lookup RDAP for ASN, and Discover Host Services. Activate when the sweep is done and you are deciding whether a host, IP, or ASN is worth a follow-up lookup or a deeper scan, or when an engagement's posture should hold you back.
---

# Recon flow: sweep first, then pivot

Run Initial Sweep is still your default entry point and your widest
net - it enumerates subdomains, probes live endpoints, scans the
top ports, and writes the inventory you then slice with the query
tools. The sweep records the surface. The pivot tools let you follow
a single thread off it when one is worth following. Most hosts never
need a pivot; reach for one when the sweep surfaced a specific reason.

## Sweep first

Always sweep before you pivot. The pivot tools take inputs the sweep
produced - the IPs behind in-scope hosts, an ASN read off an enriched
IP, the open-port map for one host. Reaching for a pivot before the
sweep means you have nothing grounded to feed it. Inspect the sweep
with List Subdomains / List Endpoints / List Open Ports first, then
decide where a thread is worth pulling.

## When to enrich an IP - Lookup IP Assets

Use Lookup IP Assets when the sweep surfaced IPs and you want to know
who owns the address space and what else lives on it. It composes the
AS-owner (which network announces the IP), the registrant and abuse
contact, and any hostnames that reverse-resolve back to the same IP.

Reach for it when:

- An in-scope host resolves to an IP in a netblock that looks
  corporate-owned rather than a shared cloud provider (AWS, Cloudflare,
  Google, Fastly and the like host thousands of unrelated tenants, so
  the netblock tells you little). A corporate netblock often hosts
  sister assets worth knowing about.
- A reverse-DNS hostname riding in on the result shares the
  programme's apex - that is a net-new in-scope candidate the sweep's
  forward enumeration missed. Promote it the same way you would a
  Certificate Transparency hit: scope-check it, then annotate.

The reverse-DNS hostnames are pivot evidence, not in-scope assets by
default. A hostname that cohabits an IP but sits outside the
programme's scope stays out - cohabitation is a lead, not permission.

## When to look up an ASN - Lookup RDAP for ASN

Lookup IP Assets already carries the registrant record for each IP, so
reach for Lookup RDAP for ASN only when the question is about the
autonomous system itself, not one address in it:

- You are building a picture of an organisation's whole address space -
  the AS-owner and its registration tell you the shape of what they
  run.
- You need the registrant or abuse contact for the network as a whole,
  for a disclosure that should reach the asset owner directly.

Pass the ASN as the bare number you read off an enriched IP. A miss
returns nothing and you move on - not every AS has a clean record.

## When to deep-scan - Discover Host Services

Discover Host Services runs a focused service / version scan against one host's
known-open ports. The sweep's port scan tells you *which* ports are
open; this tells you *what is listening* on them - service names,
version banners, the technology behind a port.

Reach for it when the sweep's open-port map shows a non-HTTP service on
an in-scope host: a database port, an SSH / RDP / SMTP banner, a
message-queue or admin port worth fingerprinting. The HTTP surface is
already covered - Discover Webpages and the sweep's httpx pass fingerprint
web technology, so a plain web host rarely needs this. Pass the ports
the sweep already found open; the scan focuses on exactly those rather
than re-sweeping.

A precise service banner feeds a HIGH-priority annotation the
Penetration Tester can act on directly: "OpenSSH 8.2p1 on 22, Postgres
13.4 on 5432" is the kind of detail that turns a port number into a
testable lead.

## When to hold back

The pivot tools are louder than passive lookups - a deep scan in
particular puts focused traffic on a host. Match the depth to the
engagement:

- A programme that forbids scanning, or limits you to manual testing,
  rules out Discover Host Services entirely - the same scope and policy
  discipline that governs the sweep governs the pivots.
- A stealthy posture means the sweep itself already ran quieter; hold
  the deep scan for the few hosts where the payoff is clear rather than
  scanning every host that shows an open port.
- When in doubt about whether a deeper look is welcome on this
  engagement, surface it to the operator rather than proceeding.

The default is still sweep, slice, annotate. The pivots are for the
handful of threads where the sweep gave you a concrete reason to look
closer - reach for them with judgement, not by reflex.
