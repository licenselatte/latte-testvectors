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
  "expect_in_grace_period": false
}
```

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

## Regenerating fixtures

```sh
cd generator
go run .
```

This overwrites everything in `vectors/`. After regenerating, every
consuming repo needs the standard two-step bump described in the top-level
porting task:

```sh
cd latte-testvectors && git commit -am "..." && git push
# in each of latte-go, latte-rs, latte-py, latte-js:
cd testdata && git pull origin main && cd ..
git add testdata && git commit -m "bump testvectors to <short-sha>"
```
