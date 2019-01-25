#!/bin/bash

echo -e "\033[0;32m[*] Deploying updates to GitHub...\033[0m"

# Build the project.
hugo -t hugo-redlounge

cd public

# Add changes to git.
git add .

# Commit changes.
msg="Build website : `date`"

if [ $# -eq 1 ]
  then msg="$1"
fi

git commit -m "$msg"

# Push source and build repos.
git push origin master

# Come Back up to the Project Root
cd ..