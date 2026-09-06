# Feature Specification: CORS Misconfiguration Probe

**Feature Branch**: `docs/cors-misconfiguration-spec`

**Created**: 2026-09-06

**Status**: Draft

**Input**: Detect web endpoints whose cross-origin resource sharing policy grants access to origins an attacker controls, so the penetration tester can report exploitable cross-origin data exposure.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Detect an exploitable CORS policy (Priority: P1)

The penetration tester points the probe at discovered endpoints. For each one it sends a cross-origin request from an origin the target has no reason to trust and inspects how the CORS policy responds. Where the policy would let an attacker's page read the endpoint's responses, the probe reports it, ranked by how directly exploitable it is.

**Why this priority**: This is the whole feature - without it there is nothing to report.

**Independent Test**: Point the probe at an endpoint that reflects an untrusted origin with credentials allowed; it reports a top-severity finding. Point it at an endpoint that validates origins; it reports nothing.

**Acceptance Scenarios**:

1. **Given** an endpoint that echoes any request `Origin` into `Access-Control-Allow-Origin` and returns `Access-Control-Allow-Credentials: true`, **When** the probe runs, **Then** it reports one finding at the highest severity, carrying the origin sent and the headers seen.
2. **Given** an endpoint that returns no CORS headers, **When** the probe runs, **Then** it reports nothing.
3. **Given** an endpoint that reflects only origins the target legitimately trusts, **When** the probe sends an untrusted origin, **Then** it reports nothing.

### User Story 2 - Rank weaker signals without dropping them (Priority: P2)

Not every permissive response is a credentialed data-theft primitive; some are only a cross-origin read of unauthenticated data, useful as a step toward a larger exploit. The probe surfaces these at a lower severity so the vulnerability researcher can judge whether they chain.

**Independent Test**: An endpoint that reflects an untrusted origin but does not allow credentials, and one that allows all origins, each produce a lower-severity finding rather than silence.

**Acceptance Scenarios**:

1. **Given** an endpoint that reflects an untrusted origin without `Access-Control-Allow-Credentials: true`, **When** the probe runs, **Then** it reports a lower-severity finding.
2. **Given** an endpoint that returns `Access-Control-Allow-Origin: *`, **When** the probe runs, **Then** it reports a lowest-severity finding.

### User Story 3 - Choose which origin probes to send (Priority: P3)

The tester can run the full set of origin probes or narrow to one when they already suspect a particular weakness, to save requests against a large surface.

**Independent Test**: Selecting only the null-origin probe sends only that origin; selecting nothing sends the full set.

**Acceptance Scenarios**:

1. **Given** a request to run only the null-origin probe, **When** the probe runs, **Then** only the `null` origin is sent.
2. **Given** no selection, **When** the probe runs, **Then** every origin probe is sent.

### Edge Cases

- Comparison of header keyword values (e.g. `true`) is case-insensitive.
- An endpoint that errors or times out on one probe does not stop the run against the remaining endpoints.
- An endpoint reachable by more than one origin probe is reported once, at its most severe result.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: WHEN the probe runs against an endpoint, the system SHALL send a cross-origin request carrying an untrusted `Origin` and read the endpoint's `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` response headers.
- **FR-002**: WHEN the response reflects the untrusted origin the probe sent AND allows credentials, the system SHALL report a finding at the highest severity.
- **FR-003**: WHEN the response reflects the untrusted origin the probe sent AND does not allow credentials, the system SHALL report a finding at a lower severity.
- **FR-004**: WHEN the response allows all origins (`Access-Control-Allow-Origin: *`), the system SHALL report a finding at the lowest severity.
- **FR-005**: IF the response grants no cross-origin access, or reflects only an origin the target legitimately trusts, THEN the system SHALL NOT report a finding for that endpoint.
- **FR-006**: The system SHALL offer at least two untrusted origin probes - an attacker-controlled origin and the `null` origin - and SHALL let the caller run all of them or a chosen subset.
- **FR-007**: WHERE more than one origin probe reports a finding for the same endpoint, the system SHALL report a single finding carrying the most severe result.
- **FR-008**: The system SHALL include, in each finding, the origin it sent and the CORS response headers it observed, so a human can reproduce the result without rerunning the probe.
- **FR-009**: The system SHALL probe only in-scope endpoints and SHALL send unauthenticated requests.
- **FR-010**: IF a network error occurs while probing one endpoint, THEN the system SHALL record no finding for it and continue with the remaining endpoints.

### Key Entities

- **Origin probe**: an untrusted `Origin` value the probe sends (an attacker-controlled origin; the `null` origin).
- **Finding**: a reported CORS weakness for one endpoint - its severity, the origin sent, and the CORS headers observed.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On a known-vulnerable endpoint (reflects an untrusted origin with credentials) the probe reports exactly one finding at the highest severity; on a known-safe endpoint it reports none.
- **SC-002**: Every severity rank in FR-002 through FR-004 is reachable and readable from a finding's reported severity.
- **SC-003**: A finding alone is sufficient to reproduce the check by hand - it names the origin sent and the headers observed.
- **SC-004**: A failure against one endpoint never suppresses results for the others.

## Assumptions

- The attacker-controlled origin is a host that does not resolve, so an over-permissive target cannot be induced to contact a real third party.
- The endpoints supplied to the probe were already scope-checked upstream.

## Out of Scope

- Origin-validation bypasses built from the target's own domain (trusted-subdomain and prefix/suffix regex tricks, e.g. `target.com.attacker.tld`).
- Preflight-only (`OPTIONS`) policies and non-GET methods.
- Judging whether a lower-severity finding actually chains into a larger exploit - the vulnerability researcher's call at triage.
