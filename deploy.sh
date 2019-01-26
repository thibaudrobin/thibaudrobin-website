#!/bin/bash

echo -e "\033[0;1;34m[*] Start building...\033[0m"

# Build the project.
hugo -t hugo-redlounge 1> /dev/null

cd public

echo -e "\033[0;1;34m[*] Deploying updates to thibaudrobin.github.io...\033[0m"

# Add changes to git.
git add .

# Commit changes.
msg="Build website : `date`"

if [ $# -eq 1 ]; then
  msg="$1"
fi

git commit -m "$msg"

# Push source and build repos.
git push origin master

if [ $? -eq 0 ]; then
  echo -e "\033[0;1;32m[+] Updates deployed !\n\033[0m"
else
  echo -e "\033[0;1;31m[x] Error during deployment...\n\033[0m"
fi

# Come Back up to the Project Root
cd ..

echo -e "\033[0;1;34m[*] Committing original project...\033[0m"

# Commit the original project
git add .
git commit -m "$msg"

# Push it
git push origin master

if [ $? -eq 0 ]; then
  echo -e "\033[0;1;32m[+] Updates saved !\033[0m"
else
  echo -e "\033[0;1;31m[x] Error during git push...\033[0m"
fi