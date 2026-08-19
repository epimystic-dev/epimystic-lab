# Project Agent Guide

This file documents how the coding agent operates in this project. Every rule
below is paired with a rationale so that a future maintainer can decide
whether it still applies. This is a deliberate practice against unbounded
instruction-file growth.

## Style

- You must use HTTPS for all outbound requests, because plaintext leaks
  bearer tokens across every proxy in the request path.
- You should prefer small pull requests (rationale: reviewers catch more
  regressions when the diff is scoped).

## Testing

- You must run the full test suite before proposing a merge, because the
  integration tier exercises code paths not covered by unit tests.
