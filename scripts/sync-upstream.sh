#!/usr/bin/env bash
# sync-upstream.sh
#
# Merges the latest changes from github.com/lqqyt2423/go-mitmproxy into this
# fork (github.com/DontBeProud/go-mitmproxy) while automatically rewriting
# the module path so that only real logic conflicts need manual resolution.
#
# Usage:
#   bash scripts/sync-upstream.sh [upstream-branch]
#
# upstream-branch defaults to "main".  The script must be run from the repo root.

set -euo pipefail

UPSTREAM_REMOTE="upstream"
UPSTREAM_BRANCH="${1:-main}"
REWRITE_BRANCH="upstream-rewritten"
OLD_MODULE="github.com/lqqyt2423/go-mitmproxy"
NEW_MODULE="github.com/DontBeProud/go-mitmproxy"

echo "==> Fetching ${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH}..."
git fetch "${UPSTREAM_REMOTE}" "${UPSTREAM_BRANCH}"

echo "==> Creating/resetting rewrite branch '${REWRITE_BRANCH}'..."
git branch -f "${REWRITE_BRANCH}" "${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH}"
git checkout "${REWRITE_BRANCH}"

echo "==> Rewriting module path in all Go/mod/md files..."
find . \( -name "*.go" -o -name "go.mod" -o -name "*.md" \) \
    -not -path "./.git/*" \
    -exec sed -i "s|${OLD_MODULE}|${NEW_MODULE}|g" {} +

echo "==> Committing rewritten upstream..."
git add -A
git diff --cached --quiet || git commit -m "chore: rewrite module path for upstream sync"

echo "==> Switching back to previous branch and merging..."
git checkout -
git merge "${REWRITE_BRANCH}" --no-ff -m "chore: sync upstream ${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH}"

echo ""
echo "Done. If there are conflicts, resolve them then run: git merge --continue"
echo "After verifying, you can delete the helper branch with: git branch -d ${REWRITE_BRANCH}"

