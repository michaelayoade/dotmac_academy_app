# Web account creation policy

`Settings.web_account_creation_role_admission`
(`WEB_ACCOUNT_CREATION_ROLE_ADMISSION`) maps target role slugs to ordered,
nonempty tuples of unique actor role slugs. Environment and stored JSON encode
these as arrays. Role names are arbitrary nonempty strings without surrounding
whitespace; there is no runtime list of built-in roles. Empty maps are valid and
admit nobody. The compatibility defaults live in Settings and the example env:
`student: [instructor, admin]`, `instructor: [admin]`, `admin: [admin]`.

`Settings.web_account_creation_password_min_length`
(`WEB_ACCOUNT_CREATION_PASSWORD_MIN_LENGTH`) defaults to zero. Zero imposes no
additional password strength minimum for this web entrypoint, preserving current
behavior. It does not bypass the required HTTP Form field, account eligibility,
role admission, genuine authority, or type validation. Positive configured values
apply the chosen minimum. Booleans, floats, negative integers, and malformed
integer text refuse. The existing reset-only minimum of eight remains independent;
this policy introduces no bootstrap, seed, invite, reset or login policy change.

The same keys in `platform_settings` override environment values. Missing rows
use current Settings values. Stored NULLs, invalid shapes, duplicate actor roles,
malformed JSON, or invalid minimum values refuse; deleting a row restores the
environment value. Direct/stored JSON rejects duplicate object keys. Environment
complex-value decoding is performed first by Pydantic Settings, so duplicate
object keys there follow its eager last-value behavior. This limitation is not a
claim of strict duplicate-key refusal for environment JSON. Settings error text
hides input values; policy errors never interpolate passwords or configuration.

`web_account_creation_policy(db)` calls `effective(db, require_store=True)`:
missing sessions and store failures refuse instead of authorizing from fallback.
The frozen `AcademyWebAccountCreationPolicy` requires all three inputs, copies the map
into immutable storage and retains no password material. Its `validate(subject,
secret)` implements the existing Kernel `PasswordPolicyPort`; `validate_account`
allows the same check before account effects. No internal role or length default
exists in the policy or factory.

`can_create_any(actor_role_slugs)` and
`can_assign_role(target_role, actor_role_slugs)` are configured admission
predicates. They are not proof of actor identity or actual grants. A future
request-bound adapter must first resolve and lock real authenticated authority,
then check `can_create_any` before rejecting an unknown target, preserving the
existing neither-actor 403 before invalid-target 400 order. Unknown targets can be
checked against `role_admission`; `can_assign_role` returns false for them. The
caller remains responsible for resolving actual target roles, locked grants,
account eligibility, precise HTTP messages, transaction/savepoint ownership,
store writes and genuine actor audit. No cached role collection, request-supplied
role, public subject reference or policy object establishes authority by itself.

This source capsule adds the policy seam only. It does not wire or activate a web
route, assign credentials, grant roles, create audit actors, or add system actor
fallback. Existing reset and invitation policy/read/null behavior and unrelated
settings remain preserved. Actual authority/store/audit composition, whole-account
rollback, hosted full runtime/database qualification, released installation and
canonical identity adoption remain separate gates. Tests are authored for hosted
CI; no local imports, runtime or database tests were executed.


`Settings.web_account_creation_role_provisioning`
(`WEB_ACCOUNT_CREATION_ROLE_PROVISIONING`) is a separate role-slug to display-name
map. The Settings compatibility defaults are exactly `student: Student`,
`instructor: Instructor`, `admin: Administrator`, preserving the legacy
`bootstrap.ensure_roles` behavior of creating every missing configured role.
Role and display-name strings must be nonempty and have no surrounding whitespace.
No runtime fixed role keys, generated display names or permission defaults exist.
An empty map explicitly means no role creation.

The immutable public `role_provisioning` map is the required third constructor
input after `role_admission` and `minimum_length`; the factory passes its actual
strict DB-over-env setting. Stored NULLs and malformed values refuse. Direct and
stored JSON duplicate keys refuse; environment JSON retains the Pydantic eager
last-value decoding limitation described above. Missing overrides use Settings.

Provisioning and admission are independent. An admitted target may already exist
in the actual catalog and need no provisioning entry. A provisioning entry need
not be an admitted target. The policy does not require either map to contain the
other, create roles or grant permissions. The future adapter must validate actor
admission, target and duplicate email first, then provision ALL configured missing
roles in canonical `Role` inside the whole-account savepoint. It must resolve and
verify actual role references through its genuine authority boundary. This capsule
adds configuration only; it does not perform database role creation.
