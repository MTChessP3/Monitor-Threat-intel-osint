#!/bin/bash
# ============================================================
# ActorTrace VIP Protection Report - Deploy Script
# ============================================================
# Usage:
#   Option 1: ./deploy.sh --github-token YOUR_GITHUB_PAT
#   Option 2: ./deploy.sh --vercel-token YOUR_VERCEL_TOKEN
#
# To create a GitHub PAT:
#   https://github.com/settings/tokens/new?scopes=repo,workflow
#
# To create a Vercel token:
#   https://vercel.com/account/tokens
# ============================================================

set -e

GITHUB_TOKEN=""
VERCEL_TOKEN=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --github-token)
      GITHUB_TOKEN="$2"
      shift 2
      ;;
    --vercel-token)
      VERCEL_TOKEN="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

PROJECT_DIR="/home/z/my-project"
cd "$PROJECT_DIR"

echo "========================================"
echo " ActorTrace VIP - Deploy Script"
echo "========================================"

# Build first
echo ""
echo "[1/3] Building project..."
npx next build

if [ $? -ne 0 ]; then
  echo "Build failed! Aborting."
  exit 1
fi

echo ""
echo "[2/3] Committing any uncommitted changes..."
git add -A
git diff --cached --quiet || git commit -m "chore: pre-deploy commit $(date +%Y%m%d-%H%M%S)"

if [ -n "$GITHUB_TOKEN" ]; then
  echo ""
  echo "[3/3] Pushing to GitHub (triggers Vercel auto-deploy)..."
  git remote set-url origin "https://${GITHUB_TOKEN}@github.com/MTChessP3/vip-protection-report.git"
  git push origin main
  git remote set-url origin "https://github.com/MTChessP3/vip-protection-report.git"
  echo ""
  echo "✅ Pushed to GitHub! Vercel will auto-deploy."
  echo "   Check: https://vercel.com/dashboard"

elif [ -n "$VERCEL_TOKEN" ]; then
  echo ""
  echo "[3/3] Deploying directly to Vercel..."
  npx vercel deploy --prod --token="$VERCEL_TOKEN" --yes
  echo ""
  echo "✅ Deployed to Vercel!"

else
  echo ""
  echo "❌ No token provided!"
  echo ""
  echo "Usage:"
  echo "  ./deploy.sh --github-token YOUR_GITHUB_PAT"
  echo "  ./deploy.sh --vercel-token YOUR_VERCEL_TOKEN"
  echo ""
  echo "Create GitHub PAT:"
  echo "  https://github.com/settings/tokens/new?scopes=repo,workflow"
  echo ""
  echo "Create Vercel token:"
  echo "  https://vercel.com/account/tokens"
  exit 1
fi
