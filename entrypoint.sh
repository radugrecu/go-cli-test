#!/bin/sh -l

echo "Hello $1"
echo "Never gonna give you up, never gonna let you down"
time=$(date)
echo "time=$time" >> $GITHUB_OUTPUT

echo "who-to-greet: ${INPUT_who-to-greet}"
echo "another_input: ${INPUT_another_input}"

printenv | grep INPUT

echo "INPUT_WHO-TO-GREET: ${INPUT_WHO-TO-GREET}"
echo "INPUT_ANOTHER_INPUT: ${INPUT_ANOTHER_INPUT}"
