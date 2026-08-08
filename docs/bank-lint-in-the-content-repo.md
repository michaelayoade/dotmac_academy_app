# Running the bank rules where the content lives

## The problem this solves

`lint_bank` lives in `dotmac_academy_app`, which has CI. 252 of the technical
question banks live in `dotmac-academy`, which has **no CI at all**. The two
repositories cannot see each other, and `pyproject.toml` sets
`package-mode = false`, so the linter cannot be `pip install`-ed either.

The result, measured on the live estate in August 2026:

| | banks | failing |
| --- | ---: | ---: |
| In this repo (management + entrance) | 82 | **0** |
| In `dotmac-academy` (technical) | 251 | **246** |

Same authors, same care. The only difference is that a machine looked at one
set and not the other. A guesser choosing the longest option scores **85%**
across those 2,075 questions, and **98%** on `routing-final`.

## The fix

`app/services/bank_lint.py` has no `app.*` and no SQLAlchemy imports — only
PyYAML and the standard library. `tests/services/test_bank_lint_standalone.py`
holds that boundary, including a subprocess run from outside the repo, because
a single stray import silently removes the gate.

It runs directly:

```bash
python app/services/bank_lint.py path/to/banks/          # a directory
python app/services/bank_lint.py path/to/bank.yaml ...   # or files
```

Exit code is 1 if any bank fails, 0 otherwise, so CI can gate on it.

## Workflow for `dotmac-academy`

Add as `.github/workflows/banks.yml`. It needs one secret — a token that can
read this repository — because the rules deliberately live in one place rather
than being copied into two.

```yaml
name: banks
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # The rules have one owner. Vendoring a copy here would let the two
      # drift, which is the failure this whole exercise exists to remove.
      - uses: actions/checkout@v4
        with:
          repository: michaelayoade/dotmac_academy_app
          path: .app
          token: ${{ secrets.ACADEMY_APP_READ_TOKEN }}
          sparse-checkout: app/services/bank_lint.py
          sparse-checkout-cone-mode: false

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install pyyaml

      # Report-only while the backlog is worked through. Remove
      # `continue-on-error` per manual as each one reaches zero failures —
      # that ratchet is what stops remediated banks drifting back.
      - name: Lint question banks
        continue-on-error: true
        run: python .app/app/services/bank_lint.py manuals/
```

## Turning the ratchet

Start report-only: 246 failures on day one would block all content work and the
workflow would simply be removed. Instead, as each manual reaches zero, move it
to a blocking step:

```yaml
      - name: Manuals that must stay clean
        run: python .app/app/services/bank_lint.py manuals/00-foundation manuals/01-fiber-engineering
```

A manual only ever moves from the report-only list to the blocking list, never
back. That is the whole mechanism: remediation without a ratchet is a thing you
do twice.

## Remediation order

Priority is learners, not alphabetical or size:

| Order | Manual | Failing | Enrolled | Note |
| ---: | --- | ---: | ---: | --- |
| 1 | `00-foundation` | 18 of 24 | **194** | 285 submissions — nearly everyone |
| 2 | `01-fiber-engineering` | 33 of 34 | 27 | 19 submissions |
| 3 | `03-routing-and-switching` | 33 of 33 | 24 | 35 submissions; final is 98% guessable |
| 4 | `02-wireless-and-radio`, `04-network-support`, `05-technical-support` | 81 | 18 each | Enrolled, not yet submitting |
| 5 | the remaining six manuals | 79 | **0** | No route to a learner today |

**Within a manual, fix the final first.** Chapter banks are practice with no
gate; a final decides pass/fail. Nobody has sat a final yet and no certificates
have been issued, so there is no historical result to correct — but that is
exactly why the window to fix them is now.
