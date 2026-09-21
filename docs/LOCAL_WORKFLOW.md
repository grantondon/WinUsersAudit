# Local development and validation

main is the only active development branch. unified-report is archived under
archives/ and must not be developed or merged unless explicitly requested.

1. Check the current branch, origin and local changes before editing.
2. Edit the local checkout. Preserve UTF-16 LE with BOM for VBS and TXT files.
3. Run `tools/Test-LocalAudit.ps1` on this computer from elevated PowerShell.
   PowerShell is a development helper only, never a collector dependency.
4. Inspect console output, all five CSV files and the diagnostic log in the
   printed validation directory. Explain every warning or unavailable value.
5. Require exit code zero, valid CSV headers and a readable ZIP containing
   the five current CSV files and the diagnostic log. Check the changed
   functionality separately; file existence alone is not success.
6. Fix failures and repeat the local run. Do not commit or push an unverified
   collector change. Confirm its SHA256 still matches the successful run.
7. Commit only reviewed source, documentation, tests and intentional archives.
   Push main only after the checks pass. Never upload local audit results.

The helper performs structural checks, not a complete semantic audit. Human
or agent review of diagnostics is required before publishing. This workflow
is a project rule, not a server-enforced GitHub branch protection.

Validation artifacts are isolated in .local-validation/ and ignored by Git.
The ZIP copy of diagnostics may be shorter than the final external log because
the existing collector appends archive results after copying diagnostics.

A successful run on this computer does not prove XP/Server 2003 compatibility.
GitHub Desktop can open this checkout. CLI Git authentication is separate and
must be verified; never place access tokens in repository files or remote URLs.
