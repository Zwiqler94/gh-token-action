#!/bin/bash

curl -L \
    -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ghs_ljYWccsSdD1AXxvp46DKHhQTQMQUai0K8bNk" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    https://api.github.com/repos/Zwiqler94/GH-Actions/pulls \
    -d '{"title":"Amazing new feature","body":"Please pull these awesome changes in!", "head":"Zwiqler94:test","base":"main"}'

curl -L \
  -X POST \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer <YOUR-TOKEN>"\
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/OWNER/REPO/branches/BRANCH/protection/restrictions/apps \
  -d '{"apps":["octoapp"]}'