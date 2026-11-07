---
name: wardenbroker
description: Get credentials (passwords, API keys, tokens, TOTP codes) from the user's Bitwarden vault through WardenBroker, with the user's approval on their phone. Use whenever a task needs a secret you don't have — never ask the user to paste one into the chat.
---

# Getting secrets with WardenBroker

The `wardenbroker` CLI asks the user's phone for a secret from their Bitwarden vault. The user sees your request, your
reason, and approves or denies it. Approved secrets are end-to-end encrypted to this machine.

## Setup

If `wardenbroker` isn't installed, install the prebuilt binary (no Go needed):

```bash
curl -fsSL https://raw.githubusercontent.com/MeLlamoPablo/WardenBroker/master/install.sh | sh
```

Then ask the user for their broker URL and register (they approve on their phone):

```bash
wardenbroker register --url <broker url> --name <a name for this agent>
```

## Rules

1. **Never ask the user to paste a secret into the conversation.** Request it with `wardenbroker`.
2. **Prefer `wardenbroker run`.** It injects secrets into a command's environment, so the value never enters your context
   or the transcript. Use `get` only when a value must be written somewhere a command can't read it from the environment.
3. **Give a specific, honest reason.** The user reads it on their lock screen. "Push the v2.3 release tag to GitHub" is
   good; "need access" will (rightly) get denied.
4. **Ask for the narrowest host** that does the job (`api.github.com`, not every GitHub item).
5. **Don't echo, log or commit secret values.** If you used `get`, don't repeat the output in your reply.
6. **A denial is an answer.** Exit code `3` means the user said no. Don't retry in a loop; tell the user what you were
   trying to do and continue without it or ask how to proceed.

## Commands

```bash
# Run a command with secrets in its environment (preferred)
wardenbroker run --reason "Deploy the staging stack" \
  -e GITHUB_TOKEN=github.com \
  -e PGPASSWORD=db.internal.example:password \
  -- ./scripts/deploy.sh

# Print a single value (password by default)
wardenbroker get github.com --reason "Clone the private repo over HTTPS"
wardenbroker get github.com --field username --reason "..."
wardenbroker get github.com --field totp --reason "..."        # current 2FA code
wardenbroker get api.openai.com --field "API Key" --reason "..." # a custom field

# Check this machine's registration
wardenbroker status
```

`-e VAR=host[:field]` takes the same field names as `--field`: `password`, `username`, `totp`, `totp-seed`, `notes`,
`uri`, or the name of a custom field.

Requests wait up to 10 minutes for the user (`--timeout` to change). Say so before running one: "I've asked for
access to github.com on your phone."

## Exit codes

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Success | Continue |
| 1 | Error (network, missing field…) | Read stderr; if a field is missing, stderr lists the available ones |
| 2 | Usage / not registered | If not registered, ask the user to run `wardenbroker register --url <broker> --name <name>` and approve it |
| 3 | Denied or agent disconnected | Stop and tell the user |
| 4 | Timed out / expired | Ask the user whether to try again |
