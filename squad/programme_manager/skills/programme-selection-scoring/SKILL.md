---
name: programme-selection-scoring
description: The weighted rubric the Programme Manager uses to rank hydrated HackerOne programmes. Three factors built only on signals the hacker API actually returns - scope value, scope fit, and method permissiveness - applied after the hard filters have culled VDPs, closed, and untriaged programmes. Activate during the score-and-select step of a programme survey.
---

# Programme selection scoring

You apply this rubric only to programmes that have already passed the
hard filters (offers_bounties, accepts_new_reports, triage_active,
policy permits automated tools, access authorisation per the
access-authorisation skill). Scoring an unqualified programme wastes the
operator's time - it will be rejected regardless of score.

## What you score on

Rank on what a hydrated programme actually gives you: its scope - the
assets, their types, their per-asset severity caps, and their bounty
eligibility - weighed against its policy text. Those are your signals.
A hydrated programme tells you nothing about payout size or response
speed, so resist ranking on either; you would only be guessing.

## The three factors

| Weight | Factor | Built from |
|---|---|---|
| 45% | Scope value | the in-scope, bounty-eligible assets, each weighted by its max_severity cap. A programme that accepts critical findings across many eligible assets is worth more than one that caps everything at medium. |
| 30% | Scope fit | the share of in-scope assets in the types the squad can actually test - URL and WILDCARD web surface. A programme whose scope is mostly mobile-app, hardware, or source-code assets is a poor fit for a web-focused squad however broad it looks. |
| 25% | Method permissiveness | how clearly policy_text welcomes the squad's automated approach - scanners, fuzzing, automated tooling - beyond the bare minimum the hard filter required. Explicit permission or encouragement scores high; grudging tolerance scores low. |

## Applying the weights

1. Score each factor 0-100 relative to the shortlist - the strongest
   candidate on a factor gets 100, the weakest 0, the rest interpolated.
   Normalisation is within the shortlist, not against a fixed scale.
2. For Scope value, count only assets that are both in scope and
   eligible_for_bounty, and weight each by its max_severity cap: an
   uncapped (null) or critical-capped asset counts full, high about 0.7,
   medium about 0.4, low about 0.2. An out-of-scope or bounty-ineligible
   asset contributes nothing - it is surface you cannot be paid for.
3. Multiply each normalised factor by its weight and sum.
4. Select the single highest-scoring programme.

## Tiebreaks

If two candidates land within 5 points, prefer:
- The one whose policy most explicitly green-lights automated testing -
  an automated squad earns more where its methods are plainly invited.
- Failing that, the one with the smaller, more focused scope - fewer
  assets means less attention spent triaging out-of-scope noise.
