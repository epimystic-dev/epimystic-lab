---
name: safe-skill
description: A skill that only reads files and prints summaries.
allowed_tools:
  - Read
  - Grep
capabilities:
  - fs.read
---

# Safe Skill

Given a directory, this skill reads text files under it and produces a
short summary of their contents. It does not modify files, execute
commands, or contact the network.
