#!/usr/bin/env bash
# Merges an upstream 3x-ui release into the fork.
#   scripts/fork-sync.sh v3.12.0
# Files that differ from upstream only by branding are taken from upstream and
# re-branded; generated files are taken from upstream and rebuilt by the caller.
# Real conflicts stay in the tree for manual resolution. Nothing is committed.
set -euo pipefail
cd "$(dirname "$0")/.."

tag=${1:?usage: scripts/fork-sync.sh <upstream tag, e.g. v3.12.0>}
[[ -z "$(git status --porcelain)" ]] || { echo "working tree is not clean" >&2; exit 1; }

git remote get-url upstream > /dev/null 2>&1 || git remote add upstream https://github.com/MHSanaei/3x-ui.git
git fetch --quiet upstream "refs/tags/${tag}:refs/tags/${tag}"
git merge --no-commit --no-ff "${tag}" || true

take_upstream=(
    install.sh update.sh x-ui.sh
    internal/web/service/panel/panel.go
    frontend/src/layouts/AppSidebar.tsx
    .github/workflows/release.yml
    internal/config/version
    docs/public/openapi.json
    frontend/public/openapi.json
)
for f in "${take_upstream[@]}"; do
    if git ls-files --unmerged -- "$f" | grep -q .; then
        git checkout --theirs -- "$f"
    fi
done
while read -r f; do
    git checkout --theirs -- "$f"
done < <(git diff --name-only --diff-filter=U -- frontend/src/generated)

bash scripts/fork-brand.sh
printf '%s-oidc.1' "${tag#v}" > internal/config/version
git add -A .github/workflows bot_context_test.go install.sh update.sh x-ui.sh internal/config/version \
    internal/web/service/panel/panel.go frontend/src/layouts/AppSidebar.tsx \
    docs/public/openapi.json frontend/public/openapi.json frontend/src/generated

conflicts=$(git diff --name-only --diff-filter=U)
if [[ -n "$conflicts" ]]; then
    echo "Resolve these by hand, then follow FORK.md:"
    echo "$conflicts"
    exit 1
fi
echo "Merged ${tag}. Next: regenerate, test and commit as described in FORK.md."
