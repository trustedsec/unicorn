# Lessons

## 2026-09-22 - Module-level globals make harness-only tests lie

What went wrong: A synthetic harness that imported unicorn.py and called `format_payload()` directly reported a `NameError: ipaddr` in the DDE path, which looked like a real bug.

What the fix was: In real usage `ipaddr` is assigned at module scope before `format_payload()` runs, so the NameError only existed in the harness. The genuine DDE bug (the stale `full_attack[11:]` strip) was confirmed by replaying a full argv-level invocation with `generate_shellcode` stubbed.

How to prevent it next time: unicorn.py relies on module-level globals set in the argument-parsing block. Verify suspected bugs through a real `sys.argv` invocation (stubbing only `generate_shellcode`/`msfvenom`), not by calling functions in isolation, before writing a fix.

## 2026-06-04 - Scoped patches to the active worktree

What went wrong: I applied a new regression test from the primary checkout, so the untracked file landed on `master` instead of the active feature worktree.

What the fix was: I deleted the accidental untracked file from the primary checkout and re-applied the same test under `.worktrees/fix-latest-github-items/`.

How to prevent it next time: When using `apply_patch` with a linked worktree, target the worktree path explicitly or change the patch path to include `.worktrees/<branch>/` before editing.
