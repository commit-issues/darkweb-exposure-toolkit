# Setup Guide — Getting Your API Keys

This tool works without any API keys — but adding them unlocks more sources.
Everything listed here is **free** except HIBP which costs $3.50/month.

---

## New to GitHub or terminals?

Before setting up this tool, check these guides first:

| Guide | Link |
|---|---|
| GitHub account setup | https://github.com/commit-issues/secure-your-repo/blob/main/docs/setup/account.md |
| SSH key setup (Mac/Linux/Windows) | https://github.com/commit-issues/secure-your-repo/blob/main/docs/setup/ssh.md |
| Securing your repo | https://github.com/commit-issues/secure-your-repo |
| Code audit standards | https://github.com/commit-issues/code-audit |

These are part of the **SudoCode** open source security series by the same author.

---

## Step 1 — Copy your .env file

In your terminal from the project folder:

```bash
cp .env.example .env
```

Open `.env` in any text editor. You will fill in each key below.

---

## Step 2 — HaveIBeenPwned API Key (optional — $3.50/month)

HIBP is the gold standard for breach checking. Without it the tool
still runs using the free sources below.

1. Go to: https://haveibeenpwned.com/API/Key
2. Enter your email address
3. Complete payment ($3.50/month — cancel anytime)
4. Check your email for your API key
5. Copy and paste it into your .env file:
   HIBP_API_KEY=paste-your-key-here

---

## Step 3 — GitHub Personal Access Token (free)

Required for scanning public GitHub repositories for exposed credentials.

1. Go to: https://github.com/settings/tokens
2. Click "Generate new token" → "Generate new token (classic)"
3. Name it: darkweb-exposure-toolkit
4. Expiration: set to your preference (90 days recommended)
5. Scopes: check ONLY "public_repo" — nothing else needed
6. Click "Generate token" at the bottom
7. IMPORTANT: Copy the token immediately — GitHub only shows it once
8. Paste into your .env file:
   GITHUB_TOKEN=paste-your-token-here

---

## Step 4 — Emailrep.io API Key (free)

Checks email reputation and breach history. Free key, no credit card.

1. Go to: https://emailrep.io/key
2. Enter your email and describe your use case (personal security monitoring)
3. Your free key arrives by email within minutes
4. Paste into your .env file:
   EMAILREP_API_KEY=paste-your-key-here

---

## Step 4b — ggshield (for the token/API-key leak check)

The token/API-key check uses a tool called **ggshield** to see if a key you
paste in has already leaked publicly — without ever sending the key itself
anywhere. Only a scrambled fingerprint of it is sent, never the real value.

This is a separate program, not something `pip3 install -r requirements.txt`
installs for you. It's optional — if you skip this, the tool still works,
it just won't offer this specific check. These steps assume you are typing
commands into a terminal (Terminal.app on macOS, or PowerShell/Command
Prompt on Windows) for the first time — every command below is exact,
copy-paste it as written.

### 4b.1 — Check if you already have `pipx`

`pipx` is a small program that installs tools like `ggshield` safely, off
to the side, so it can't interfere with anything else on your computer.
Type this and press Enter:

```bash
pipx --version
```

**If you see a version number** (e.g. `1.7.1`), skip to step 4b.3 — you
already have it.

**If you see an error** like `command not found: pipx` or
`'pipx' is not recognized`, continue to step 4b.2.

### 4b.2 — Install `pipx`

**macOS / Linux:**

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
```

**Windows (PowerShell):**

```powershell
python -m pip install --user pipx
python -m pipx ensurepath
```

After running these two commands, you'll see some text scroll by — that's
normal. Once it's done, **close your terminal window completely and open a
new one.** This step is required — the second command changes a setting
that only takes effect in a brand new terminal window.

In the new window, confirm it worked:

```bash
pipx --version
```

You should now see a version number. If you still see an error, restart
your computer once and try again — this resolves it in almost all cases.

### 4b.3 — Install `ggshield`

`ggshield` is pinned to an exact version here rather than left open —
since it lives outside `requirements.txt`, it does not get automatic
`pip-audit` coverage. Check `pipx list --outdated` occasionally and
review the changelog before bumping this version.

```bash
pipx install ggshield==1.52.2
```

**What success looks like:** a few lines of text ending with something
like:

```
  installed package ggshield 1.52.2, installed using Python 3.x.x
  These apps are now globally available
    - ggshield
done! ✨ 🌟 ✨
```

Confirm it's really there:

```bash
ggshield --version
```

**What success looks like:** a single line such as `ggshield, version
1.52.2`. If instead you see `command not found` / `not recognized`, close
and reopen your terminal one more time (same reason as step 4b.2 — pipx
just changed your PATH and your current terminal window hasn't picked it
up yet), then try `ggshield --version` again.

### 4b.4 — That's it — no account needed

Unlike the other sources in this guide, **you do not need to sign up for
anything** to use the basic token-leak check — it works anonymously with a
daily usage limit. The tool will tell you exactly how many checks you have
left each time you run it.

If you want a higher daily limit, you can optionally create a free account
at https://dashboard.gitguardian.com, generate an API key from your
dashboard, and paste it into your `.env` file as:

```
GITGUARDIAN_API_KEY=paste-your-key-here
```

This is entirely optional and nothing is shared or bundled on your behalf
— it's your own key, from your own free account, same as every other key
in this guide.

---

## Step 5 — OSINTLeak API Key (free starter)

Checks stealer logs and dark web forum data. Free starter plan available.

1. Go to: https://osintleak.com
2. Click Sign Up
3. Choose the free starter plan
4. Go to: Account Settings → API Key
5. Copy your key
6. Paste into your .env file:
   OSINTLEAK_API_KEY=paste-your-key-here

---

## Step 6 — Fill in your identifiers

Still in your .env file, add what you want to check:

```
EMAILS_TO_CHECK=your@email.com,another@email.com
USERNAMES_TO_CHECK=yourusername,anotherusername
PHONES_TO_CHECK=+12125551234
```

Phone numbers must include country code (e.g. +1 for USA, +44 for UK).

---

## Step 7 — Run the tool

```bash
python3 src/run_all_checks.py
```

That is it. Results are saved locally to data/exposure.db on your machine only.
Nothing is sent anywhere except the API calls you configured above.

---

## No API keys at all?

The tool still works. These sources require no keys:

- LeakCheck — 7 billion+ breach records
- BreachDirectory — passwords and hashes
- psbdmp.ws — paste site dumps

Just fill in your identifiers in .env and run. You will still get real results.

---

## Protecting your .env file

Your .env file contains sensitive keys. It is already in .gitignore so it
will never be committed to git. Keep it safe:

```bash
chmod 600 .env
```

This makes the file readable only by you.
