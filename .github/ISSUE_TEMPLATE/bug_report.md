---
name: Bug report
about: Something is broken or behaves unexpectedly
title: "bug: <short description>"
labels: bug
assignees: ''
---

<!--
Before filing:
  - For SECURITY issues, do NOT use this template. Email per SECURITY.md.
  - Search existing issues to avoid duplicates.
  - If you're on a stale checkout, pull main first and confirm the bug still reproduces.
-->

## Summary

One sentence describing what is broken.

## Steps to reproduce

1. ...
2. ...
3. ...

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened. Include full tracebacks, error messages, and any relevant log lines (`docker compose logs web`, browser console, etc.). Wrap them in triple backticks.

```
<paste here>
```

## Environment

- Vulnex version / commit: <!-- e.g. v0.5.0 or commit hash from `git rev-parse HEAD` -->
- Install method: <!-- docker compose / native / fly.io -->
- Python: <!-- `python --version` -->
- OS: <!-- e.g. Ubuntu 24.04 / Windows 11 / macOS 14 -->
- Browser (if UI bug): <!-- e.g. Firefox 124, Chrome 122 -->

## Screenshots / screen recording

If the bug is visual, attach a screenshot or short clip. Drag-drop into the box.

## Anything else?

Workarounds you've tried, related issues, custom configuration, anything that might help narrow it down.
