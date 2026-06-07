# H1 API cheatsheet

## GET `program/{handle}`

```python
r = requests.get(
  'https://api.hackerone.com/v1/hackers/programs/{handle}',
  auth=('<YOUR_API_USERNAME>', '<YOUR_API_TOKEN>'),
  headers = headers
)
```

Yields JSON:

```json
{
  "data": {
    "id": 9,
    "type": "program",
    "attributes": {
      "handle": "acme",
      "name": "acme",
      "currency": "usd",
      "policy": "acme's program policy.",
      "profile_picture": "/assets/global-elements/add-team.png",
      "submission_state": "open",
      "triage_active": null,
      "state": "public_mode",
      "started_accepting_at": null,
      "number_of_reports_for_user": 0,
      "number_of_valid_reports_for_user": 0,
      "bounty_earned_for_user": 0,
      "last_invitation_accepted_at_for_user": null,
      "bookmarked": false,
      "allows_bounty_splitting": false,
      "offers_bounties": true,
      "open_scope": true,
      "fast_payments": true,
      "gold_standard_safe_harbor": false
    },
    "relationships": {
      "structured_scopes": {
        "data": []
      }
    }
  }
}
```

## GET `programs`

```python
r = requests.get(
  'https://api.hackerone.com/v1/hackers/programs',
  auth=('<YOUR_API_USERNAME>', '<YOUR_API_TOKEN>'),
  headers = headers
)
```

Yields JSON:

```json
{
  "data": [
    {
      "id": 9,
      "type": "program",
      "attributes": {
        "handle": "acme",
        "name": "acme",
        "currency": "usd",
        "policy": "acme's program policy.",
        "profile_picture": "/assets/global-elements/add-team.png",
        "submission_state": "open",
        "triage_active": null,
        "state": "public_mode",
        "started_accepting_at": null,
        "number_of_reports_for_user": 0,
        "number_of_valid_reports_for_user": 0,
        "bounty_earned_for_user": 0,
        "last_invitation_accepted_at_for_user": null,
        "bookmarked": false,
        "allows_bounty_splitting": false,
        "offers_bounties": true,
        "open_scope": true,
        "fast_payments": true,
        "gold_standard_safe_harbor": false
      }
    }
  ],
  "links": {}
}
```

## GET `weaknesses`

```python
r = requests.get(
  'https://api.hackerone.com/v1/hackers/programs/{handle}/weaknesses',
  auth=('<YOUR_API_USERNAME>', '<YOUR_API_TOKEN>'),
  headers = headers
)
```

Yields JSON:

```json
{
  "data": [
    {
      "id": "1337",
      "type": "weakness",
      "attributes": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
        "created_at": "2016-02-02T04:05:06.000Z",
        "external_id": "cwe-352"
      }
    },
    {
      "id": "1338",
      "type": "weakness",
      "attributes": {
        "name": "SQL Injection",
        "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
        "created_at": "2016-03-02T04:05:06.000Z",
        "external_id": "cwe-89"
      }
    }
  ],
  "links": {}
}
```
`
## GET `structured_scopes`


```python
r = requests.get(
  'https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes',
  auth=('<YOUR_API_USERNAME>', '<YOUR_API_TOKEN>'),
  headers = headers
)
```

Yields JSON:

```json
{
  "data": [
    {
      "id": "<id>",
      "type": "structured-scope",
      "attributes": {
        "asset_type": "URL",
        "asset_identifier": "https://api.hackerone.com",
        "eligible_for_bounty": true,
        "eligible_for_submission": true,
        "instruction": "This is our API",
        "max_severity": "critical",
        "created_at": "<date>",
        "updated_at": "<date>",
        "confidentiality_requirement": "high",
        "integrity_requirement": "high",
        "availability_requirement": "high"
      }
    }
  ],
  "links": {
    "self": "http://api.test.host/v1/hackers/programs/acme/structured_scopes?page%5Bsize%5D=1",
    "next": "http://api.test.host/v1/hackers/programs/acme/structured_scopes?page%5Bnumber%5D=2&page%5Bsize%5D=1",
    "last": "http://api.test.host/v1/hackers/programs/acme/structured_scopes?page%5Bnumber%5D=3&page%5Bsize%5D=1"
  }
}
```

## GET scope_exclusions


```python
r = requests.get(
  'https://api.hackerone.com/v1/hackers/programs/{handle}/scope_exclusions',
  auth=('<YOUR_API_USERNAME>', '<YOUR_API_TOKEN>'),
  headers = headers
)
```

Yields JSON:

```json{
  "data": [
    {
      "id": "123",
      "type": "scope-exclusion",
      "attributes": {
        "category": "Custom exclusion name",
        "details": "Description of what is excluded",
        "created_at": "2024-01-01T00:00:00.000Z",
        "updated_at": "2024-01-01T00:00:00.000Z"
      }
    }
  ]
}
```