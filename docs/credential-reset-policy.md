# Account reset policy composition

Source candidate based on Academy `a5ffe6316e97bf33e17ef9c1f00788796f5e5a5a`.
This capsule is not an installed or activated assembly.

`app.services.credential_policy` owns the Academy reset-only policy and its
settings-backed factory. `password_reset_policy(db)` reads the actual caller
Session through `settings_store.effective(db, require_store=True)`. Pass the
result explicitly as `password_policy` to the reset adapter's
`complete_password_reset`. The adapter has no default policy or minimum.

`Settings.password_reset_min_length` / `PASSWORD_RESET_MIN_LENGTH` declares the
historical reset default of 8 characters. The existing Academy settings store
registers `password_reset_min_length` in `KNOWN_KEYS`, integer coercion, minimums,
live defaults and `EffectiveSettings`. A stored value overrides environment
configuration; absent/null values use configuration. Configuration strings are
parsed as decimal positive integers; booleans, floats, blanks, zero, negatives
and malformed values refuse. Writes validate before any mutation. Clearing a
stored override with null retains the existing settings-store semantics.

The frozen `AcademyPasswordPolicy(minimum_length)` requires a typed positive
integer with no default. Its `validate_account(secret)` performs the early rule;
its `validate(subject, secret)` implements `PasswordPolicyPort` for each real
`CredentialSubjectRef`. Failures never quote password material. Alternate
reviewed policy implementations can satisfy the adapter's structural
`AccountPasswordPolicy` contract with both methods.

Reset policy composition fails on an unavailable settings store, missing
Session, unknown effective policy shape or malformed persisted minimum. The
strict read option is additive; existing non-policy callers retain the store's
best-effort behavior. The factory does not open a Session, commit, roll back,
hash a password or authorize a token. Composition must resolve the factory in
the existing caller transaction before credential effects and pass the same
policy through early and per-member validation. No policy result is cached.

This setting does not apply to web/bootstrap creation (which currently has no
strength rule) or seed's separate existing policy. It adds no reset route wiring,
schema migration, settings UI, owner release, deployment or qualification claim.
The future Kernel public credential contract and the reset-adapter source slice
must be composed before hosted runtime checks can execute.

`tests/test_credential_policy_settings.py` covers declared/default/environment
settings, DB-over-env resolution with the real factory Session, strict read
failure, malformed values, pre-mutation write refusal, typed construction and
both policy methods. Tests are written, not run locally. Only the repository's
pinned Ruff static checks and standard-library source inspection are allowed
locally; hosted CI remains responsible for runtime and integration evidence.
