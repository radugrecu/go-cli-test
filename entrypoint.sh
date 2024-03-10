#!/bin/sh -l

echo "Hello $1"
echo "Never gonna give you up, never gonna let you down"
time=$(date)
echo "time=$time" >> $GITHUB_OUTPUT

echo "who-to-greet: ${INPUT_who-to-greet}"
echo "another_input: ${INPUT_another_input}"

printenv | grep INPUT