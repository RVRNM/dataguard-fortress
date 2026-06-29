#!/bin/bash
# Execute this script ONLY after creating an anonymous GitHub account
# and logging in with `gh auth login`

set -euo pipefail
cd "$(dirname "$0")/.."

USERNAME="dataguard-fortress"  # Change to your anon username
REPO="dataguard-fortress"

echo "Creating repo $USERNAME/$REPO on GitHub..."
gh repo create "$REPO" --public --description "Privacy proxy for AI agents — PII scrub + classify + audit"

echo "Adding remote and pushing..."
git remote add origin "https://github.com/$USERNAME/$REPO.git"
git push -u origin main --tags

echo ""
echo "✅ Push complete! Repo is live at:"
echo "   https://github.com/$USERNAME/$REPO"
echo ""
echo "Next steps:"
echo "   1. Add topics: privacy, proxy, pii, ai-agent, security"
echo "   2. Enable Issues"
echo "   3. Pin the repo"
echo "   4. Share on Reddit r/selfreddit, HN, Twitter"
