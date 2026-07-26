# Git workflow

Always cut branches fresh from a current main. Do not reuse or rebase a branch that was used for a previous PR - once a PR merges, its commits are in main and rebasing on top of them causes conflicts that require skipping commits. Place the branch in a folder depending on the semantics of the change. The correct flow every time for a feature:

```bash
git fetch origin
git checkout main
git pull origin main
git checkout -b feat/your-branch-name
```

Substitute `feat/` for the appropriate prefix from the type table below.

A `git diff origin/main --stat` before any push is a fast sanity check that only your intended changes are included.

## Commit and branch type prefixes

This repo follows [Conventional Commits](https://www.conventionalcommits.org/). Branch prefixes match commit types so the two stay in lockstep and `commitizen` lands cleanly when it's wired up.

Format: `<type>(<scope>)?: <subject>` for commit messages, `<type>/<short-description>` for branch names. Scope is optional but encouraged when it sharpens the subject - e.g. `chore(coverage):`, `fix(recon):`, `docs(git-workflow):`.

| Type | When to use |
|---|---|
| `feat` | A new feature visible to a user or another agent |
| `fix` | A bug fix |
| `docs` | Documentation only - no code or test change |
| `style` | Formatting, whitespace, missing semicolons - no logic change |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | A change that improves performance |
| `test` | Adding or correcting tests - no production code change |
| `build` | Build system or dependency changes (`pyproject.toml` deps, packaging) |
| `ci` | CI configuration only (`.github/workflows/`, pre-commit hooks) |
| `chore` | Maintenance that doesn't fit the above - bumping a gate value, tidying a config |
| `revert` | Reverts a previous commit; subject is the reverted commit's subject |

Examples:

- `feat(squad/triage): add CVSS sanity-check pass after vulnerability researcher`
- `fix(recon/scope): treat sub.example.com as in-scope when pattern is example.com`
- `chore(coverage): raise fail_under from 70 to 88`
- `docs(git-workflow): document --force-with-lease policy`

## One issue, one branch, one PR

For each GitHub issue worked on, present a single branch with a single PR for review. Do not bundle multiple issues into one PR even if they touch adjacent files - reviewer attention is the bottleneck, not branch count. If mid-task you discover unrelated work that needs doing, capture it as a `# FIXME` or `# TODO` (see the FIXME/TODO grammar in `CONTRIBUTING.md`) or as a new issue, and finish the original task first.

## Force-push policy

- **Never** force-push to `main` or any protected/shared branch.
- **Never** force-push to a PR branch (in review or not) without an explicit, plain-words authorisation from the maintainer in the immediately preceding message. Pre-review and in-review make no difference - ask. `--force-with-lease` is no exception; the lease check only prevents stomping concurrent work, not the deliberate history rewrite the maintainer has not approved.
- Vented frustration ("just force-push it then", "no way around it") is **not** authorisation. The maintainer's word for "yes do it" is what counts.
- `git push --delete`, `git branch -D` on shared branches, and `git push origin <sha>:<branch>` carry the same risk as `--force` and need the same authorisation.

## Merging upstream into a feature branch

When `main` has moved on and you need its changes in your feature branch, **merge, do not rebase**:

```bash
git checkout main
git fetch origin
git pull origin main          # main is now identical to origin/main
git checkout feat/your-branch
git merge main                # resolve conflicts here, on the feature branch
git push origin feat/your-branch
```

Resolve conflicts on the feature branch and push the merge commit. The PR diff still shows your branch's net additions against current main; reviewers see your work, not the absorbed main commits.

Rebase is a tool for cleaning up your own un-pushed commits before opening a PR. Do **not** reach for it to "tidy" a published PR branch - rebase rewrites commit SHAs, which means a force-push, which means an unauthorised history rewrite per the policy above. If a published PR branch has accumulated noise that genuinely needs cleaning, ask the maintainer; do not assume.

## Branch identity

When a PR exists, the PR's head branch is the canonical workspace for that work. Do all follow-up commits on that branch directly.

Never open a parallel "rebase branch", "fixup branch", or "cleanup branch" to do PR work on - even when a harness, generator, or AI session creates one and tells you to use it. The PR branch is what reviewers, CI, and the maintainer's mental model are anchored to. A second branch with overlapping content fragments review and invites force-push as the cleanup mechanism.

If a harness has placed you on a synthetic branch when a real PR branch exists for the same work, switch to the PR branch and surface the mismatch to the maintainer before making changes.

## Commit messages

Never include session URLs in commit messages. Links of the form `https://claude.ai/code/session_...` embed a reference to a private conversation and must not appear in commit history. Use a plain one- or two-sentence description instead.
