#!/bin/sh -l

if [ -z "${INPUT_GITHUB_TOKEN}" ] ; then
  echo "Consider setting a GITHUB_TOKEN to prevent GitHub api rate limits." >&2
fi

ls -la
