#!/usr/bin/env bash
# Commits and pushes every hour, prints the link to the latest commit.
# Usage: ./scripts/autopush.sh   (run once: git remote add origin <your-repo-url>)
set -u
INTERVAL="${INTERVAL:-3600}"
while true; do
  git add -A
  git commit -m "chore: hourly progress $(date -u +%Y-%m-%dT%H:%MZ)" >/dev/null 2>&1 || echo "nothing new to commit"
  if git push origin HEAD 2>&1; then
    url=$(git remote get-url origin | sed -E 's#git@github.com:#https://github.com/#; s#\.git$##')
    echo "PUSHED -> ${url}/commit/$(git rev-parse HEAD)"
  else
    echo "push failed - check remote/credentials"
  fi
  sleep "$INTERVAL"
done
