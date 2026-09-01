# latte-testvectors

Shared, language-agnostic test vectors for `latte-go`, `latte-rs`, `latte-py`,
and `latte-js`. Every SDK's test suite runs every fixture in `vectors/` and
must agree on the outcome. This is the actual cross-language deliverable,
proof that all implementations agree, not just that each one has tests.

## Layout

```
generator/    Go program that produces every file in vectors/.
              Regenerate with: cd generator && go run . 
vectors/      The fixtures themselves (checked in, not built by consumers).
              vectors/manifest.json is a flat index of name/category/expect
              for quick scripting; the per-fixture .json files are the
              source of truth.
```

## Fixture schema

Each `vectors/<name>.json` is:

```json
{
  "name": "valid_fresh",
  "category": "valid_license",
  "description": "human-readable explanation of what this exercises",
  "now": "2026-07-04T12:00:00Z",

  "master_public_key_hex": "<64 lowercase hex chars, the root pubkey to verify against>",
  "machine_id": "<opaque string to pass as the machineID / mid comparison input>",

  "token": "<activation JWT, compact serialization>",
  "chain": {
    "submaster": "<submaster cert JWT>",
    "project": "<project cert JWT>",
    "daily": "<daily cert JWT>"
  },

  "expect": "accept | reject",
  "expect_stage": "none | verify | validate",
  "expect_reason": "see taxonomy below; empty string when not applicable",
  "expect_in_grace_period": false,

  "expect_has_entitlements": false,
  "expect_entitlements": {}
}
```

`expect_has_entitlements` and `expect_entitlements` are only meaningful for
an accepted fixture; see "Entitlements" below.

**`now` must be injected as the verifier's current time**, not read from the
real system clock, that's what makes every fixture reproducible regardless
of when or where the test suite runs. Every SDK's core verification
function needs a way to accept an explicit "current time" for exactly this
reason.

The signing keys embedded in these fixtures are **test-only** and bear no
relationship to any real LicenseLatte production key. `master_public_key_hex`
per fixture is whichever key the fixture wants the verifier to check
against — for `wrong_verification_key`, this is deliberately *not* the key
that actually signed the chain.

## Running the fixtures against a port

Pseudocode every SDK's fixture-runner test follows:

```
for each vectors/*.json (skip manifest.json):
    load fixture
    license, verify_err = verify_chain(fixture.master_public_key_hex, fixture.token, fixture.chain, now=fixture.now)
    if verify_err:
        assert fixture.expect == "reject" and fixture.expect_stage == "verify"
        continue
    assert not (fixture.expect == "reject" and fixture.expect_stage == "verify")

    validate_err = validate(license, fixture.machine_id, now=fixture.now)
    if validate_err:
        assert fixture.expect == "reject" and fixture.expect_stage == "validate"
        assert reason_for(validate_err) == fixture.expect_reason
        continue

    assert fixture.expect == "accept"
    assert in_grace_period(license, now=fixture.now) == fixture.expect_in_grace_period

    assert license.has_entitlements == fixture.expect_has_entitlements
    assert license.entitlements == fixture.expect_entitlements
    for key, value in fixture.expect_entitlements:
        if value is a boolean:
            assert license.can(key) == value
            assert license.limit(key) is missing      # no coercion
        else:
            assert license.limit(key) == value
            assert license.can(key) is false          # no coercion
    assert license.can("no_such_key") is false
    assert license.limit("no_such_key") is missing
```

## `expect_reason` taxonomy

latte-go itself only distinguishes failure *reasons* at the `validate`
stage (via sentinel errors) — every `verify`-stage failure (bad signature,
broken chain, malformed input, wrong key, clock skew on a cert, cross-check
failures) is a single generic wrapped error in latte-go with no sentinel
type, so fixtures at that stage only assert `expect_stage == "verify"`,
not a specific reason. `expect_reason` is only meaningful when
`expect_stage == "validate"`:

| `expect_reason` | latte-go sentinel | Meaning |
|---|---|---|
| `hard_expired` | `ports.ErrLicenseInactiveOrExpired` | `now > ExpiresAt` |
| `grace_expired` | `ports.ErrGracePeriodExpired` | `now > IssuedAt + GracePeriod`, but not yet past `ExpiresAt` |
| `license_too_old` | `ports.ErrLicenseTooOld` | `now - IssuedAt > 365 days`, independent of `ExpiresAt`/`GracePeriod` |
| `machine_id_mismatch` | none (generic error) | caller-supplied machine ID doesn't match the token's `mid` claim |

A port is free to expose a richer/finer error taxonomy at the `verify`
stage than latte-go does (e.g. a dedicated "chain broken" vs "signature
invalid" exception type), that's a reasonable, idiomatic improvement, not
a deviation that needs a `PORTING_NOTES.md` entry, as long as `expect` and
`expect_stage` still match for every fixture. Collapsing the `validate`
stage's four reasons into fewer buckets, or ignoring `now` in favor of the
real system clock, is not acceptable and breaks the parity guarantee this
repo exists to provide.

## Entitlements

Six fixtures in the `entitlements` category cover the typed-entitlements
claim (`ent`) described in `license-latte-api/docs/typed-entitlements.md`.
Every one of them **accepts**: an entitlement value an SDK cannot represent
must never invalidate a licence, because the machine holding that licence
is one nobody can reach to correct the mistake.

| Fixture | Pins |
|---|---|
| `entitlements_absent` | No `ent` claim. Every `can()` false, every `limit()` missing, `has_entitlements` false. |
| `entitlements_bool_and_int` | The happy path, including a *present* `false`. |
| `entitlements_unlimited` | `-1` round-trips as `-1`, not as a maximum and not as a miss. |
| `entitlements_malformed_value_dropped` | A string, a fractional number, an object, an array and a null are each dropped; the good keys survive; the licence still accepts. |
| `entitlements_type_mismatch` | `can()` on an int key and `limit()` on a bool key both miss. `seat_count: 0` and `is_pro: true` are the values that would split five implementations if any of them coerced. |
| `entitlements_empty_object` | `"ent": {}` is identical to absent for every accessor, and differs only in `has_entitlements`. |

The rules every port must implement, in full:

1. **Never fail on a malformed value.** Drop the entry, keep the licence.
2. **Absent denies.** `can()` false, `limit()` missing. There is no
   "unknown means allow": the token is a bearer artefact on the machine of
   the person it constrains, so if absence granted, stripping the claim
   would unlock everything.
3. **No coercion across kinds.** `can()` on an integer is false, not
   "nonzero is true". `limit()` on a boolean misses, rather than returning
   0 or 1.
4. **Byte-exact key comparison.** No case folding, no trimming, no Unicode
   normalisation. The server enforces `^[a-z][a-z0-9_]{0,63}$` at write
   time so clients never have to.
5. **`UNLIMITED` is `-1`,** returned as-is; callers compare against the
   constant each SDK exports.
6. **Only whole numbers are integers.** `25` and `25.0` are both the
   integer 25; `1.5` is dropped. Go's and JavaScript's JSON parsers hand
   back a float for all three, so a rule that distinguished `25` from
   `25.0` is one two of the five SDKs could not implement.

`has_entitlements` is a first-class part of the contract, not a
convenience accessor. Absence denies, so a seller who ships `can()` before
their installed base has renewed would switch their own feature off for
every cached token issued before the claim existed. The probe is what lets
them write "if the token knows about entitlements use them, otherwise keep
the old behaviour" for one release.

## Regenerating fixtures

```sh
cd generator
go run .
```

This overwrites everything in `vectors/`. Every chain is signed with
freshly generated keys, so a full run rewrites every fixture even when
nothing about it changed. That is harmless — the agreement this repo
exists to prove is over *outcomes*, not over bytes — but it is noise in a
review, so when adding fixtures without touching the schema, filter
instead and leave the rest of the vectors alone:

```sh
cd generator
go run . -only entitlements_
```

`manifest.json` is written in full either way — its fields are all
key-independent — so a filtered run never leaves a name out of the index.

A change to the fixture *schema* (a new `expect_*` field) still needs a
full run, since every fixture has to carry every field. After regenerating, every
consuming repo needs the standard two-step bump described in the top-level
porting task:

```sh
cd latte-testvectors && git commit -am "..." && git push
# in each of latte-go, latte-rs, latte-py, latte-js:
cd testdata && git pull origin main && cd ..
git add testdata && git commit -m "bump testvectors to <short-sha>"
```
