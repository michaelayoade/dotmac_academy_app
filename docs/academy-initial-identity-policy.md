# Initial canonical identity state

Source-only policy slice based on the closed 225-file canonical identity-store capsule. No activation or runtime qualification is claimed.

`Settings.account_initial_is_active=True` and `Settings.account_initial_profile_status="active"` preserve prior creation behavior. Environment examples expose both settings. Restricted settings-writer helpers validate values before mutation and retain stored NULL values so strict composition refuses them. A missing row uses the current Settings value; a NULL, malformed value or store-read failure refuses. The status is an exact built-in string of at most 20 characters, matching VARCHAR(20); empty, whitespace and multibyte content are preserved without a new enum.

Each new invitation or direct web identity composes one frozen `InitialIdentityPolicy` after the existing prerequisite checks and immediately before its first identity/role DML. Both arguments are required. The policy contains state, never authority. Persisted values must match the private snapshot; settings changes during an operation affect only a subsequent operation. Reused invitation accounts retain their actual state. Fresh custom_fields/prefs dictionaries and absent avatar remain structural no-supplied-facts shapes.

Current actor activation/profile, cookie expiry/revocation, root/session identity, exact grants, credential absence and audit checks remain fixed security requirements. Web credential snapshots retain the actual target boolean, including False. Invitation claim preserves the target state; inactive or suspended targets remain unable to authenticate.

Hosted canaries are authored, NOT RUN. The actual released Kernel106 lacks assignment APIs. Qualification, release and installation of the existing future Kernel change33 contract is a prerequisite; this slice allocates no successor and changes no Kernel API. Complete committed assembly and HTTP qualification, canonical fixtures, common-lock writer participation and source integration remain owed. Local validation is limited to stdlib source/AST/hash checks and the pinned Ruff executable.
