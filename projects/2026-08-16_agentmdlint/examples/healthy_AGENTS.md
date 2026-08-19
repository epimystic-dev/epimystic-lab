# Project Agent Guide

This is an example of a *healthy* agent instruction file: it opens with a
purpose paragraph, each imperative carries its own rationale on the same
line, and the file stays small enough for a maintainer to hold in their head.

## Style

- You must use HTTPS for all outbound requests, because plaintext leaks
  bearer tokens across every proxy in the request path.
- You should prefer small pull requests, because reviewers catch more
  regressions when the diff is scoped.

## Testing

- You must run the full test suite before proposing a merge, because the
  integration tier exercises code paths not covered by unit tests.
