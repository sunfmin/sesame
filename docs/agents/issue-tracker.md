# Issue tracker: factorium

Issues for this repo live in factorium's local tracker on this host, not in
GitHub Issues: factorium does not read GitHub. `<checkout>` is this repo's
name in `factorium checkout list` (`sesame`).

- Read: `factorium issue list sesame`, `factorium issue show sesame <n>`
- File: `factorium issue add sesame <title> --body-file - [--blocked-by <n> …]`.
  Give dependencies when filing: an issue with no blocker is ready, and a
  worker takes it on the next tick.
- Comment: `factorium issue comment sesame <n> …`
- Dependencies: `factorium issue block sesame …`

There are no labels: whether an issue can start is decided only by its
blockers.
