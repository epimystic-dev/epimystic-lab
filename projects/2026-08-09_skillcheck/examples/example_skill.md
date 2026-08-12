---
name: fetch-and-summarise
description: Fetch a text file from a trusted local path and print a short summary.
allowed_tools:
  - Read
capabilities:
  - fs.read
---

# fetch-and-summarise

Given a local file path, read the file and print the first 300 words plus
a bullet-list summary of the top three noun phrases. Does not modify
files, execute shell commands, or contact the network.

## Steps

1. Read the file at the provided path.
2. Extract the first 300 words.
3. Produce a three-bullet summary.
4. Return the summary.

## Non-goals

- No file writes.
- No network access.
- No shell execution.
