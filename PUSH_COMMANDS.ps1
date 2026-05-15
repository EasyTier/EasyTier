# Push to wuhins repository
# Run these commands in PowerShell from the repository root

cd "C:\Users\HINS\Documents\Trae\EasyTier"

# Check current status
git status

# Stage all changes
git add -A

# Commit with the prepared message
git commit -F COMMIT_MESSAGE.txt

# Push to wuhins remote on the current branch
git push wuhins feature/dynamic-connector-refresh

Write-Host "Push completed to wuhins/feature/dynamic-connector-refresh"
