# V4Z IP Guard — RASHDIPGuardTermuxx

An **honest** Termux IP tool: see your real public IP, prove whether Tor actually changed it, score your setup, keep an IP history, and test your own local proxies.

Built by **V4Z RASHD** — Telegram: [@rashdteem](https://t.me/rashdteem)

> Most "IP changer" scripts fake the result. This one shows proof: direct IP vs Tor exit IP side by side, verified through the Tor Project's own check endpoint.

## Install (Termux)

```bash
curl -fsSL https://raw.githubusercontent.com/v4zrashd/RASHDIPGuardTermuxx/main/install.sh | bash
```

Then run:

```bash
v4zip
```

## Commands

| Command | What it does |
|---|---|
| `v4zip` | Interactive menu |
| `v4zip check` | Your current public IP + country/city/ISP |
| `v4zip tor start` | Start Tor (needs `pkg install tor`) |
| `v4zip tor ip` | Your Tor exit IP |
| `v4zip tor stop` | Stop the Tor started by v4zip |
| `v4zip compare` | Direct IP vs Tor exit IP — are they really different? |
| `v4zip score` | Privacy score (0–10) from observable signals |
| `v4zip log` | IP change history |
| `v4zip report` | Save a text session report |
| `v4zip proxy test` | Test proxies from your local `proxies.txt` |
| `v4zip proxy run` | Rotate through your list, showing each exit IP |

## Proxies (optional)

Put **your own** list in `./proxies.txt` or `~/.v4zip/proxies.txt` — one per line:

```
host:port:user:pass
scheme://user:pass@host:port
host:port
```

**Keep that file only on your phone. Never upload it to GitHub or share it.** Passwords are masked in tool output.

## Honest limitations

- On a non-rooted phone, no tool can magically rewrite your carrier IP. A real switch happens through **Tor** or a **proxy** — apps only use a proxy if pointed at it.
- The privacy score is a simple, transparent heuristic from what the tool can observe — not a full anonymity audit.
- Proxy support assumes you are authorized to use the proxies in your list. You are responsible for how you use this tool.

## Requirements

- Termux with Python 3 (installer handles it)
- Optional: `pkg install tor` for the Tor features
- Pure Python standard library — no pip installs

---

© V4Z RASHD — [@rashdteem](https://t.me/rashdteem)
