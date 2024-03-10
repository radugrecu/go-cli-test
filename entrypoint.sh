#!/bin/sh -l

echo "Hello $1"
echo "Never gonna give you up, never gonna let you down"
time=$(date)
echo "time=$time" >> $GITHUB_OUTPUT

