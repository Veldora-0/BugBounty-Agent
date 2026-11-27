# BugBounty-Agent — Runtime Data and OpenCode Working Directory

BugBounty-Agent stores program scope, asset inventories, findings, evidence, reports, and logs in the directory tree opened in OpenCode. It does not create a default `~/BugBounty-Workspace` on Kali.

## 1. How the workspace is selected

The workspace root is resolved in this order:

1. `BUGBOUNTY_WORKSPACE`, only when an operator explicitly sets it.
2. The current working directory of the OpenCode session.

The normal program path is:

```text
<OpenCode working directory>/programs/<program-name>/
```

For example, when OpenCode is opened in `~/Desktop/BugBounty-Agent`, running `bb-init cleanshot` creates `~/Desktop/BugBounty-Agent/programs/cleanshot/`. OpenCode commands and the `bb-*` CLIs use the same current directory, so run them from the directory containing the program workspace. Each program receives a separate private directory.

`bb-init --workspace-dir <path>`, `bb-plan --workspace-root <path>`, and `bb-arise --workspace-root <path>` remain explicit overrides. Do not set `BUGBOUNTY_WORKSPACE` if you want the active OpenCode directory to determine storage.

## 2. Program directory layout

`bb-init <program-name>` creates this structure under `programs/<program-name>/`:

```text
programs/<program-name>/
├── scope/
│   ├── scope.yaml
│   └── program.yaml
├── targets/
├── recon/
├── web/
├── js/
├── api/
├── scans/
├── evidence/
├── findings/
├── reports/
├── state/
└── logs/
```

The directory has private permissions. Scope rules, credentials, raw captures, findings, and reports stay on the local machine. When the OpenCode directory is a Git checkout, the root `programs/` ignore rule keeps these runtime files out of normal Git status and commits. `.gitignore` is not an access-control boundary: do not force-add runtime data, and use a separate non-repository directory in OpenCode when you require physical separation from source code.

## 3. Existing home-directory workspace

Older releases defaulted to `~/BugBounty-Workspace/programs/<program-name>`. The new default does not read, move, or delete that existing data. The legacy workspace can be selected deliberately with `BUGBOUNTY_WORKSPACE` or the relevant explicit CLI override while it is being migrated. Review the destination and check for name collisions before copying program data; never overwrite an existing workspace automatically.

## 4. Git and data handling

The repository ignores `programs/`, runtime state, evidence, scans, reports, findings, logs, credentials, and private key files. Keep secrets and target data local, review `git status` before committing, and never commit customer data or bounty evidence. Hashes can detect evidence changes; they do not encrypt evidence.

The scope engine remains the authority for network actions. Selecting a local working directory does not grant authorization to test any target.
