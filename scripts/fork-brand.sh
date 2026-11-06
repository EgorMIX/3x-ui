#!/usr/bin/env bash
# Points everything that downloads or updates the panel at this fork, and trims
# the upstream CI down to what the fork needs. Safe to run repeatedly: fork-sync.sh
# runs it after every upstream merge. The repository name lives in .fork-repo.
set -euo pipefail
cd "$(dirname "$0")/.."

repo=$(tr -d '[:space:]' < .fork-repo)
[[ "$repo" == */* ]] || { echo ".fork-repo must hold owner/name" >&2; exit 1; }

sed -i -E "s#/MHSanaei/3x-ui#/${repo}#g" \
    install.sh update.sh x-ui.sh \
    internal/web/service/panel/panel.go \
    frontend/src/layouts/AppSidebar.tsx
sed -i -E "s#raw\.githubusercontent\.com/mhsanaei/3x-ui/master/#raw.githubusercontent.com/${repo}/main/#g; s#raw\.githubusercontent\.com/mhsanaei/3x-ui/#raw.githubusercontent.com/${repo}/#g" \
    install.sh update.sh x-ui.sh

# Releases come from version tags only, so a push to main ships nothing.
sed -i '1,20{/^    branches:$/d;/^      - main$/d}' .github/workflows/release.yml
# The Windows version resource takes numbers only, not the -oidc.N suffix.
sed -i -E 's/^( *PANEL_VERSION=\$\(tr .*\))$/\1; PANEL_VERSION=${PANEL_VERSION%%-*}/' .github/workflows/release.yml

# Upstream's bots, docs site and image publishing have no place in the fork.
rm -f .github/workflows/claude-issue-analyst.yml \
      .github/workflows/claude-pr-review.yml \
      .github/workflows/codeql.yml \
      .github/workflows/docker.yml \
      .github/workflows/docs-ci.yml \
      .github/workflows/docs-deploy.yml \
      .github/workflows/mutation.yml \
      bot_context_test.go
