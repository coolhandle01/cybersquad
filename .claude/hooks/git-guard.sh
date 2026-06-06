#!/usr/bin/env bash
#
# Claude Code PreToolUse hook for Bash.
#
# Hard-blocks destructive git history/branch operations at the tool boundary
# so an AI contributor cannot rewrite published history or delete shared
# branches without an explicit, plain-words maintainer authorisation. This is
# the belt-and-braces complement to docs/git-workflow.md's force-push policy:
# the doc states the rule, this hook enforces it mechanically.
#
# Blocked (deny -> the model is told why and asked to seek authorisation):
#   - git push --force / -f / --force-with-lease           (history rewrite)
#   - git push --delete / git push <remote> :<branch>      (remote deletion)
#   - git push <remote> <sha>:<branch>                     (sha-refspec push)
#   - git branch -D / --delete --force                     (force branch delete)
#   - git reset --hard                                     (working-tree nuke)
#   - git clean -f                                         (untracked nuke)
#
# Deliberately NOT blocked: ordinary `git push`, `git push -u origin <branch>`,
# `git merge`, `git rebase` of un-pushed local commits. The policy targets
# rewriting/deleting what others are anchored to, not normal forward progress.
#
# Wired via .claude/settings.json. Fails OPEN on anything unexpected (missing
# jq, unparseable input) - a guard that wedges every Bash call is worse than
# the risk it mitigates, and the doc-level policy still stands behind it.
#
set -uo pipefail

trap 'exit 0' ERR

command -v jq >/dev/null 2>&1 || exit 0

input=$(cat)
command=$(echo "$input" | jq -r '.tool_input.command // ""')
[ -z "$command" ] && exit 0

# Only inspect git invocations.
case "$command" in
    *git*) ;;
    *) exit 0 ;;
esac

# True if any whitespace-delimited token contains a ':' that is a git refspec
# separator (src:dst), as opposed to a URL scheme (https://) or scp-style
# remote (git@host:path). Used only after we know the segment is a `git push`.
_has_push_refspec() {
    local tok
    for tok in $1; do
        case "$tok" in
            *://*) continue ;;          # https:// , ssh:// , git://
            *@*:*) continue ;;          # scp-style: git@github.com:owner/repo
            *:*)   return 0 ;;          # src:dst or :dst (delete)
        esac
    done
    return 1
}

# Classify a single command segment. Echoes a reason string and returns 0 if
# the segment is a dangerous git invocation, else returns 1. The segment is
# only inspected when its FIRST token is `git` - so a commit message or
# here-doc body that merely mentions "git push --force" is never matched, only
# an actual `git ...` command is. This is what keeps the guard from blocking
# its own commit whose message describes the commands it blocks.
_classify_segment() {
    local seg="$1"
    # Trim leading whitespace, then require `git` as the first word.
    seg="${seg#"${seg%%[![:space:]]*}"}"
    case "$seg" in
        git|git\ *) ;;
        *) return 1 ;;
    esac

    # Pad + collapse whitespace for position-independent flag matching.
    local norm
    norm=" $(printf '%s' "$seg" | tr -s ' ') "

    local re_push_force=' push (.* )?(--force|--force-with-lease|-f)( |$)'
    local re_push_delete=' push (.* )?(--delete|-d)( |$)'
    local re_branch_force=' branch (.* )?-D( |$)'
    local re_reset_hard=' reset (.* )?--hard( |$)'
    local re_clean_force=' clean (.* )?-[a-eg-z]*f| clean (.* )?--force( |$)'

    if [[ $norm =~ $re_push_force ]]; then
        printf '%s' "git push --force / --force-with-lease rewrites published history."
    elif [[ $norm =~ $re_push_delete ]]; then
        printf '%s' "git push --delete removes a remote branch."
    elif [[ $norm =~ ' push ' ]] && _has_push_refspec "$norm"; then
        # Explicit <src>:<dst> refspec - `push origin :branch` (delete) or
        # `push origin sha:branch` (overwrite). Plain `push origin branch` has
        # no colon. URL/scp remotes are excluded by _has_push_refspec.
        printf '%s' "git push with an explicit <src>:<dst> refspec can delete or overwrite a remote branch."
    elif [[ $norm =~ $re_branch_force ]] || { [[ $norm =~ ' branch ' ]] && [[ $norm =~ --delete ]] && [[ $norm =~ --force ]]; }; then
        printf '%s' "git branch -D force-deletes a branch, discarding unmerged commits."
    elif [[ $norm =~ $re_reset_hard ]]; then
        printf '%s' "git reset --hard discards uncommitted work and can rewind a branch."
    elif [[ $norm =~ $re_clean_force ]]; then
        printf '%s' "git clean -f permanently deletes untracked files."
    else
        return 1
    fi
    return 0
}

# Split the command into segments on shell separators (; && || | and
# newlines) so each git invocation is judged on its own, and a here-doc /
# commit-message body (which does not start with `git`) is never judged at
# all. tr maps every separator char to a newline, then we read line by line.
reason=""
segmented=$(printf '%s' "$command" | tr ';|&\n' '\n\n\n\n')
while IFS= read -r seg; do
    [ -z "$seg" ] && continue
    if r=$(_classify_segment "$seg"); then
        reason="$r"
        break
    fi
done <<SEGMENTS
$segmented
SEGMENTS

[ -z "$reason" ] && exit 0

message="Blocked by .claude/hooks/git-guard.sh: ${reason}

Per docs/git-workflow.md, this needs an explicit plain-words maintainer authorisation in the immediately preceding message. Vented frustration is not authorisation. If you have it, ask the maintainer to run the command, or have them confirm and adjust this guard. Do not work around it with a second branch."

jq -n --arg msg "$message" '
    {
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: $msg
        }
    }
'

exit 0
