// Command generator builds the shared cross-language test vectors consumed
// by latte-go, latte-rs, latte-py, and latte-js. It signs real JWTs with
// github.com/golang-jwt/jwt/v5 (the exact library latte-go uses) so the
// byte-for-byte wire format matches production exactly. The signing keys
// here are test-only and have no relationship to any real LicenseLatte
// production key.
//
// Every fixture's "now" field is the timestamp the verifying SDK must use
// as its current time when running the fixture (inject it, don't read the
// system clock) so results are 100% reproducible.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const issuer = "licenselatte"

// anchor is the fixed reference instant every fixture's timestamps are
// expressed relative to. Using a fixed anchor (rather than time.Now())
// keeps generated fixtures byte-identical across regenerations.
var anchor = time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)

type keyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newKeyPair() keyPair {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return keyPair{pub: pub, priv: priv}
}

func hexPub(kp keyPair) string {
	return hex.EncodeToString(kp.pub)
}

func sign(priv ed25519.PrivateKey, claims jwt.MapClaims) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	s, err := tok.SignedString(priv)
	if err != nil {
		panic(err)
	}
	return s
}

func unixT(t time.Time) int64 { return t.Unix() }

// chain holds a full signed cert chain plus the keys used to build it, so
// individual fixtures can mutate one link and re-derive the rest.
type chainSet struct {
	master, submaster, project, daily keyPair

	submasterCert, projectCert, dailyCert string
}

func buildStandardChain() chainSet {
	return buildChain(anchor.AddDate(0, 0, -60), anchor.AddDate(0, 0, 60))
}

// buildNarrowChain mints a daily cert with a tight +/-1 day validity window,
// used by the clock-skew fixtures where we need the verifier's "now" to
// fall outside the daily cert's own iat/exp on purpose.
func buildNarrowChain() chainSet {
	return buildChain(anchor.AddDate(0, 0, -1), anchor.AddDate(0, 0, 1))
}

// buildDayChain mints the daily cert the server issues for the UTC day
// starting at dayStart: valid from 00:00 to 00:05 the next day.
func buildDayChain(dayStart time.Time) chainSet {
	return buildChain(dayStart, dayStart.AddDate(0, 0, 1).Add(5*time.Minute))
}

// buildChain mints a full chain whose daily cert is valid from dailyIat to
// dailyExp; the submaster and project certs comfortably cover anchor.
func buildChain(dailyIat, dailyExp time.Time) chainSet {
	return buildChainUnder(newKeyPair(), dailyIat, dailyExp)
}

// buildChainUnder is buildChain with the root that signs the submaster cert
// chosen by the caller, so several chains can hang off one set of roots.
func buildChainUnder(master keyPair, dailyIat, dailyExp time.Time) chainSet {
	submaster := newKeyPair()
	project := newKeyPair()
	daily := newKeyPair()

	submasterCert := sign(master.priv, jwt.MapClaims{
		"iss": issuer,
		"iat": unixT(anchor.AddDate(-1, 0, 0)),
		"exp": unixT(anchor.AddDate(1, 0, 0)),
		"spk": hexPub(submaster),
	})
	projectCert := sign(submaster.priv, jwt.MapClaims{
		"iss": issuer,
		"iat": unixT(anchor.AddDate(0, -6, 0)),
		"exp": unixT(anchor.AddDate(0, 6, 0)),
		"ppk": hexPub(project),
		"pid": projectID,
	})
	dailyCert := sign(project.priv, jwt.MapClaims{
		"iss": issuer,
		"iat": unixT(dailyIat),
		"exp": unixT(dailyExp),
		"dpk": hexPub(daily),
	})

	return chainSet{
		master: master, submaster: submaster, project: project, daily: daily,
		submasterCert: submasterCert, projectCert: projectCert, dailyCert: dailyCert,
	}
}

const (
	projectID    = "proj_11111111-1111-1111-1111-111111111111"
	licenseKey   = "AHAK85T628WZ639CMVHF8TNDDX260Z"
	activationID = "act_22222222-2222-2222-2222-222222222222"
	machineID    = "test-machine-001"
)

type activationOpts struct {
	iat, exp     time.Time
	graceSeconds int64
	ltype        string
	machineID    string
	metadata     map[string]string

	// entitlements becomes the `ent` claim (docs/typed-entitlements.md §2.1).
	// It is typed map[string]any rather than a typed value struct precisely
	// so a fixture can put a string, a float or a nested object in there and
	// pin what every SDK must do with it: drop the entry, keep the licence.
	entitlements map[string]any
	// hasEntitlements emits the claim even when entitlements is empty. An
	// absent claim and `"ent": {}` deny identically, so only the presence
	// probe can tell them apart -- which is the distinction it exists for.
	hasEntitlements bool

	// lexFormat signs the token the way the server does from the root
	// switch on: no `grc`, `exp` is the offline deadline itself, and `lex`
	// carries the licence's own end date when it has one (zero lex = absent).
	lexFormat bool
	lex       time.Time
}

func signActivation(cs chainSet, o activationOpts) string {
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   licenseKey,
		"aid":   activationID,
		"pid":   projectID,
		"mid":   o.machineID,
		"ltype": o.ltype,
		"iat":   unixT(o.iat),
		"exp":   unixT(o.exp),
	}
	if o.lexFormat {
		if !o.lex.IsZero() {
			claims["lex"] = unixT(o.lex)
		}
	} else {
		claims["grc"] = o.graceSeconds
	}
	if o.metadata != nil {
		claims["pmd"] = o.metadata
	}
	if o.hasEntitlements {
		ent := o.entitlements
		if ent == nil {
			ent = map[string]any{}
		}
		claims["ent"] = ent
	}
	return sign(cs.daily.priv, claims)
}

// fixture is the canonical, language-agnostic test-vector shape documented
// in SPEC.md section 2.3.
type fixture struct {
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Now         time.Time `json:"now"`

	MasterPublicKeyHex string `json:"master_public_key_hex"`
	MachineID          string `json:"machine_id"`

	Token string `json:"token"`
	Chain struct {
		Submaster string `json:"submaster"`
		Project   string `json:"project"`
		Daily     string `json:"daily"`
	} `json:"chain"`

	// RenewalFailed is the verifier's in-memory flag: true when the SDK
	// tried to renew the token and could not reach the server. It is an
	// input to in_grace_period, never derived from the token.
	RenewalFailed bool `json:"renewal_failed"`

	// Expect describes the required outcome. See ../README.md for the
	// full taxonomy every SDK's fixture runner must implement.
	Expect        string `json:"expect"`        // "accept" | "reject"
	ExpectStage   string `json:"expect_stage"`  // "none" | "verify" | "validate"
	ExpectReason  string `json:"expect_reason"` // see README taxonomy; "" when ExpectStage == "verify" or "none" and accepted
	ExpectInGrace bool   `json:"expect_in_grace_period"`

	// ExpectHasEntitlements is the presence probe: true iff the token
	// carried an `ent` claim at all, empty object included. It is not
	// derivable from ExpectEntitlements, since an absent claim and an
	// empty one both resolve to no entitlements (§2.3, §6.3).
	ExpectHasEntitlements bool `json:"expect_has_entitlements"`
	// ExpectEntitlements is the resolved map after the SDK has dropped
	// every value that is neither a boolean nor an integer. Always an
	// object, never null, so a consumer can iterate it unconditionally.
	ExpectEntitlements map[string]any `json:"expect_entitlements"`
}

// withEnt annotates a fixture with its expected entitlement outcome. Kept as
// a post-hoc setter rather than two more parameters on mk(), which already
// takes ten.
func (f fixture) withEnt(has bool, ent map[string]any) fixture {
	f.ExpectHasEntitlements = has
	if ent != nil {
		f.ExpectEntitlements = ent
	}
	return f
}

// withRenewalFailed sets the renewal_failed input; mk() leaves it false.
func (f fixture) withRenewalFailed(failed bool) fixture {
	f.RenewalFailed = failed
	return f
}

func main() {
	// Every chain here is signed with freshly generated keys, so a full run
	// rewrites every fixture byte-for-byte even when nothing about them
	// changed. -only exists so that *adding* fixtures does not invalidate
	// the ones five SDKs have already agreed on: the manifest is still
	// written in full (its fields are all key-independent), only the
	// matching vector files are.
	only := flag.String("only", "", "write only fixtures whose name contains this substring; the manifest is always written in full")
	out := flag.String("out", "", "output directory (default ../vectors, or the first positional argument)")
	flag.Parse()

	outDir := "../vectors"
	if arg := flag.Arg(0); arg != "" {
		outDir = arg
	}
	if *out != "" {
		outDir = *out
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}

	var fixtures []fixture

	// --- 1. valid, fresh ---
	{
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
			metadata: map[string]string{"tier": "pro"},
		})
		fixtures = append(fixtures, mk(cs, tok, "valid_fresh", "valid_license",
			"Freshly issued license, verified at the moment of issuance.",
			anchor, machineID, "accept", "none", "", false))
	}

	// --- 2. valid, inside grace period ---
	{
		cs := buildStandardChain()
		iat := anchor.Add(-2 * time.Hour)
		tok := signActivation(cs, activationOpts{
			iat: iat, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "valid_in_grace_period", "valid_license",
			"Issued 2h ago (past the 60-minute renewal marker) with a 7-day grace window; still accepted and InGracePeriod should read true.",
			anchor, machineID, "accept", "none", "", true).
			withRenewalFailed(true))
	}

	// --- 3. valid, past grace period (expired) — two flavors ---
	{
		cs := buildStandardChain()
		iat := anchor.AddDate(0, 0, -10)
		tok := signActivation(cs, activationOpts{
			iat: iat, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "expired_past_grace_deadline", "past_grace_period",
			"Issued 10 days ago with only a 7-day grace window; hard expiry is still a month out, so this must fail specifically on the grace deadline, not hard expiry.",
			anchor, machineID, "reject", "validate", "grace_expired", false))
	}
	{
		cs := buildStandardChain()
		iat := anchor.AddDate(0, 0, -40)
		tok := signActivation(cs, activationOpts{
			iat: iat, exp: anchor.AddDate(0, 0, -1), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "expired_hard_expiry", "past_grace_period",
			"ExpiresAt is already in the past; must fail on hard expiry.",
			anchor, machineID, "reject", "validate", "hard_expired", false))
	}

	// --- a perpetual_fixed token gets no exemption from the grace window ---
	{
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor.AddDate(0, 0, -40), exp: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
			graceSeconds: int64(30 * 24 * time.Hour / time.Second), ltype: "perpetual_fixed", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "perpetual_fixed_past_grace_deadline", "past_grace_period",
			"A token carrying ltype perpetual_fixed is validated like any other: 40 days offline against a 30-day grc must fail on the grace deadline despite a 2099 exp.",
			anchor, machineID, "reject", "validate", "grace_expired", false))
	}

	// --- 4. tampered payload (single bit flipped in the signed portion) ---
	{
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		tok = flipBitInPayload(tok)
		fixtures = append(fixtures, mk(cs, tok, "tampered_payload", "tampered_payload",
			"Single bit flipped inside the activation JWT's payload segment after signing; signature no longer matches.",
			anchor, machineID, "reject", "verify", "verify_error", false))
	}

	// --- 5. invalid signature (correct format, wrong signature bytes) ---
	{
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		tok = corruptSignature(tok)
		fixtures = append(fixtures, mk(cs, tok, "invalid_signature", "invalid_signature",
			"Well-formed JWT (correct header/payload) but the signature segment's bytes are wrong.",
			anchor, machineID, "reject", "verify", "verify_error", false))
	}

	// --- 6. broken cert chain (correct leaf signature, wrong intermediate) ---
	{
		cs := buildStandardChain()
		rogue := newKeyPair()
		// Project cert is signed by a rogue key instead of the real submaster,
		// even though its "ppk" claim still points at the real project key
		// (so the activation token's own signature stays perfectly valid).
		rogueProjectCert := sign(rogue.priv, jwt.MapClaims{
			"iss": issuer,
			"iat": unixT(anchor.AddDate(0, -6, 0)),
			"exp": unixT(anchor.AddDate(0, 6, 0)),
			"ppk": hexPub(cs.project),
			"pid": projectID,
		})
		cs.projectCert = rogueProjectCert
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "broken_cert_chain", "broken_cert_chain",
			"Project cert is signed by a key that isn't the submaster's — the activation JWT and daily cert are both perfectly valid, but the chain doesn't actually connect back to the master key.",
			anchor, machineID, "reject", "verify", "verify_error", false))
	}

	// --- 7. malformed / corrupt file (truncated, garbage bytes) ---
	{
		cs := buildStandardChain()
		fixtures = append(fixtures, mk(cs, "not-a-jwt-at-all", "malformed_garbage_token", "malformed",
			"Token is plain garbage text, not JWT-shaped at all.",
			anchor, machineID, "reject", "verify", "verify_error", false))
	}
	{
		cs := buildStandardChain()
		full := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		truncated := full[:len(full)-20]
		fixtures = append(fixtures, mk(cs, truncated, "truncated_token", "malformed",
			"Activation JWT truncated mid-signature.",
			anchor, machineID, "reject", "verify", "verify_error", false))
	}

	// --- 8. empty file ---
	{
		cs := buildStandardChain()
		f := mk(cs, "", "empty_file", "empty_file",
			"Completely empty token and cert chain.",
			anchor, machineID, "reject", "verify", "verify_error", false)
		f.Chain.Submaster = ""
		f.Chain.Project = ""
		f.Chain.Daily = ""
		fixtures = append(fixtures, f)
	}

	// --- 9. wrong verification key supplied ---
	{
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		f := mk(cs, tok, "wrong_verification_key", "wrong_key",
			"The chain and token are perfectly valid, but the verifier is configured with a different (unrelated) master public key than the one that actually signed the submaster cert.",
			anchor, machineID, "reject", "verify", "verify_error", false)
		wrongMaster := newKeyPair()
		f.MasterPublicKeyHex = hexPub(wrongMaster)
		fixtures = append(fixtures, f)
	}

	// --- 10. clock skew edge cases ---
	{
		// Verifier's clock is behind the daily cert's own iat -> the cert
		// JWT parse itself fails ("token used before issued") with the
		// library's default zero leeway, independent of grace-period math.
		cs := buildNarrowChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.Add(12 * time.Hour), graceSeconds: int64(6 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		now := anchor.AddDate(0, 0, -2) // before daily cert's iat (anchor-1d)
		fixtures = append(fixtures, mk(cs, tok, "clock_skew_before_cert_validity", "clock_skew",
			"Verifying machine's clock is set before the daily cert's own iat; must hard-fail chain verification with zero leeway, even though the activation token itself would otherwise be fine.",
			now, machineID, "reject", "verify", "verify_error", false))
	}
	{
		// Verifier's clock is ahead of the daily cert's own exp. The daily
		// cert's exp is not held against the clock, so the chain verifies;
		// the token's own exp has passed, so validate rejects it.
		cs := buildNarrowChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.Add(12 * time.Hour), graceSeconds: int64(6 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		now := anchor.AddDate(0, 0, 2) // after daily cert's exp (anchor+1d)
		fixtures = append(fixtures, mk(cs, tok, "clock_skew_after_cert_validity", "clock_skew",
			"Verifying machine's clock is set after the daily cert's own exp. The daily cert's exp is not checked against the clock (a cached token must outlive the day it was issued), so the chain verifies; the token's own exp has passed, so validate rejects it as hard-expired.",
			now, machineID, "reject", "validate", "hard_expired", false))
	}
	{
		// Activated at 23:59 UTC with the server's real daily window
		// (00:00 to 00:05 next day), verified five days later while still
		// offline. The daily cert expired days ago; the grace period, not
		// the daily cert, decides how long the token works offline.
		dayStart := time.Date(anchor.Year(), anchor.Month(), anchor.Day(), 0, 0, 0, 0, time.UTC)
		cs := buildDayChain(dayStart)
		iat := dayStart.Add(23*time.Hour + 59*time.Minute)
		tok := signActivation(cs, activationOpts{
			iat: iat, exp: iat.AddDate(0, 6, 0), graceSeconds: int64(30 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		now := iat.AddDate(0, 0, 5)
		fixtures = append(fixtures, mk(cs, tok, "offline_after_daily_cert_expiry", "clock_skew",
			"Activated at 23:59 UTC under the server's daily window (00:00 to 00:05 next day), verified five days later inside a 30-day grace period. The daily cert's exp is not checked against the clock, so this must ACCEPT, in grace.",
			now, machineID, "accept", "none", "", true).
			withRenewalFailed(true))
	}
	{
		// The daily key signed a token dated after its own cert's exp. The
		// clock is inside the token's validity, so only the iat-within-
		// daily-window cross-check can reject it.
		dayStart := time.Date(anchor.Year(), anchor.Month(), anchor.Day(), 0, 0, 0, 0, time.UTC)
		cs := buildDayChain(dayStart)
		iat := dayStart.AddDate(0, 0, 1).Add(10 * time.Minute) // after the daily exp at 00:05
		tok := signActivation(cs, activationOpts{
			iat: iat, exp: iat.AddDate(0, 6, 0), graceSeconds: int64(30 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "activation_iat_after_daily_cert_exp", "broken_cert_chain",
			"Activation JWT's iat is after its daily cert's exp, so the daily key signed a token dated outside its own day. Must hard-fail chain verification even though the verifier's clock is within the token's validity.",
			iat.Add(time.Hour), machineID, "reject", "verify", "verify_error", false))
	}
	{
		// Activation token's own iat is slightly in the future relative to
		// "now", but the cert chain's validity window comfortably covers
		// both — the activation JWT's own iat/exp/nbf check is neutralized
		// by the ~100-year leeway latte-go applies only at that layer, so
		// this must still be ACCEPTED.
		cs := buildStandardChain()
		now := anchor
		tok := signActivation(cs, activationOpts{
			iat: anchor.Add(1 * time.Hour), exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "clock_skew_activation_future_iat_tolerated", "clock_skew",
			"Activation JWT's own iat is 1h ahead of the verifier's clock; the activation JWT layer uses an effectively infinite leeway in latte-go so this is still ACCEPTED (the cert chain's own iat/exp windows are unaffected and comfortably valid).",
			now, machineID, "accept", "none", "", false))
	}

	// --- bonus: documented cross-checks from SPEC.md ---
	{
		cs := buildStandardChain()
		// Project cert's pid claim disagrees with the activation JWT's pid.
		badProjectCert := sign(cs.submaster.priv, jwt.MapClaims{
			"iss": issuer,
			"iat": unixT(anchor.AddDate(0, -6, 0)),
			"exp": unixT(anchor.AddDate(0, 6, 0)),
			"ppk": hexPub(cs.project),
			"pid": "proj_99999999-9999-9999-9999-999999999999",
		})
		cs.projectCert = badProjectCert
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "project_id_mismatch", "broken_cert_chain",
			"Project cert's own pid claim disagrees with the activation JWT's pid claim.",
			anchor, machineID, "reject", "verify", "verify_error", false))
	}
	{
		cs := buildStandardChain()
		// Activation iat predates the daily cert's own iat.
		tok := signActivation(cs, activationOpts{
			iat: anchor.AddDate(0, 0, -70), exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "activation_iat_before_daily_cert_iat", "broken_cert_chain",
			"Activation JWT claims to have been issued before the daily cert (its own signer) existed.",
			anchor, machineID, "reject", "verify", "verify_error", false))
	}
	{
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(91 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "grace_period_exceeds_90_day_ceiling", "broken_cert_chain",
			"grc claim of 91 days exceeds the hardcoded 90-day ceiling.",
			anchor, machineID, "reject", "verify", "verify_error", false))
	}
	{
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "machine_id_mismatch", "past_grace_period",
			"Chain and token are perfectly valid, but the caller-supplied machine ID doesn't match the token's mid claim.",
			anchor, "a-completely-different-machine", "reject", "validate", "machine_id_mismatch", false))
	}

	// --- grace-period boundary conditions (exact threshold, +/-1s) ---
	{
		iat := anchor.AddDate(0, 0, -7)
		grace := int64(7 * 24 * time.Hour / time.Second)
		mkBoundary := func(name string, now time.Time, expect, reason string, inGrace bool) fixture {
			cs := buildStandardChain()
			tok := signActivation(cs, activationOpts{
				iat: iat, exp: anchor.AddDate(0, 1, 0), graceSeconds: grace,
				ltype: "expiring", machineID: machineID,
			})
			return mk(cs, tok, name, "grace_boundary",
				fmt.Sprintf("Grace boundary check at now=%s (deadline=iat+7d=%s).", now.Format(time.RFC3339), iat.Add(7*24*time.Hour).Format(time.RFC3339)),
				now, machineID, expect, mapStage(expect), reason, inGrace)
		}
		// At the exact deadline, sinceActivation (7d) is not < GracePeriod (7d), so InGracePeriod is false.
		fixtures = append(fixtures, mkBoundary("grace_boundary_exact_deadline", iat.Add(7*24*time.Hour), "accept", "", false))
		// One second before the deadline, sinceActivation is strictly < GracePeriod, so InGracePeriod is true.
		fixtures = append(fixtures, mkBoundary("grace_boundary_one_second_before", iat.Add(7*24*time.Hour).Add(-time.Second), "accept", "", true).
			withRenewalFailed(true))
		fixtures = append(fixtures, mkBoundary("grace_boundary_one_second_after", iat.Add(7*24*time.Hour).Add(time.Second), "reject", "grace_expired", false))
	}

	// --- lex format: exp is the offline deadline, lex the licence's end ---
	//
	// A token without `grc` is read this way: reject past `exp`, reporting
	// hard_expired when `lex` has also passed and grace_expired otherwise;
	// reject past `lex` even if `exp` is later; GracePeriod is exp - iat.
	{
		lexCase := func(name, description string, iat, exp, lex, now time.Time, expect, reason string, inGrace bool) fixture {
			ltype := "perpetual"
			if !lex.IsZero() {
				ltype = "expiring"
			}
			cs := buildStandardChain()
			tok := signActivation(cs, activationOpts{
				iat: iat, exp: exp, lex: lex, lexFormat: true,
				ltype: ltype, machineID: machineID,
			})
			return mk(cs, tok, name, "lex_format", description, now, machineID, expect, mapStage(expect), reason, inGrace)
		}
		week := 7 * 24 * time.Hour
		var none time.Time

		iat := anchor.Add(-2 * 24 * time.Hour)
		fixtures = append(fixtures, lexCase("lex_perpetual_valid",
			"No lex (perpetual), issued 2 days ago with exp at iat+7d: accepted, and in the grace period.",
			iat, iat.Add(week), none, anchor, "accept", "", true).
			withRenewalFailed(true))

		iat = anchor.Add(-8 * 24 * time.Hour)
		fixtures = append(fixtures, lexCase("lex_perpetual_offline_too_long",
			"No lex (perpetual), exp at iat+7d passed a day ago: rejected as grace_expired.",
			iat, iat.Add(week), none, anchor, "reject", "grace_expired", false))

		iat = anchor.Add(-10 * time.Minute)
		fixtures = append(fixtures, lexCase("lex_expiring_valid",
			"lex a month out, exp at iat+7d, issued 10 minutes ago: accepted, not yet in the grace period.",
			iat, iat.Add(week), anchor.AddDate(0, 1, 0), anchor, "accept", "", false))

		iat = anchor.Add(-8 * 24 * time.Hour)
		fixtures = append(fixtures, lexCase("lex_offline_past_exp_licence_running",
			"lex a month out but exp (iat+7d) passed a day ago: rejected as grace_expired, not hard_expired.",
			iat, iat.Add(week), anchor.AddDate(0, 1, 0), anchor, "reject", "grace_expired", false))

		iat = anchor.Add(-2 * 24 * time.Hour)
		fixtures = append(fixtures, lexCase("lex_exp_cut_short_by_licence_end",
			"The licence ends tomorrow, so the server set exp = lex instead of iat+7d: accepted, in the grace period.",
			iat, anchor.Add(24*time.Hour), anchor.Add(24*time.Hour), anchor, "accept", "", true).
			withRenewalFailed(true))

		iat = anchor.Add(-10 * 24 * time.Hour)
		fixtures = append(fixtures, lexCase("lex_licence_ended",
			"exp = lex, both a day ago: rejected as hard_expired.",
			iat, anchor.Add(-24*time.Hour), anchor.Add(-24*time.Hour), anchor, "reject", "hard_expired", false))

		iat = anchor.Add(-2 * 24 * time.Hour)
		fixtures = append(fixtures, lexCase("lex_passed_before_exp",
			"lex passed an hour ago but exp is days out: lex is a hard limit on its own, rejected as hard_expired.",
			iat, iat.Add(week), anchor.Add(-time.Hour), anchor, "reject", "hard_expired", false))

		iat = anchor.Add(-7 * 24 * time.Hour)
		fixtures = append(fixtures, lexCase("lex_exp_boundary_exact",
			"now == exp: still accepted; at the deadline sinceActivation is not < GracePeriod, so not in the grace period.",
			iat, anchor, none, anchor, "accept", "", false))
		fixtures = append(fixtures, lexCase("lex_exp_boundary_one_second_after",
			"now == exp + 1s: rejected as grace_expired.",
			iat, anchor.Add(-time.Second), none, anchor, "reject", "grace_expired", false))
		iat = anchor.Add(-24 * time.Hour)
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: iat, exp: iat.Add(91 * 24 * time.Hour), lexFormat: true,
			ltype: "perpetual", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "lex_grace_over_cap", "lex_format",
			"exp - iat is 91 days, over the 90-day grace ceiling that also bounds grc: rejected at verify, so a leaked daily key cannot sign a token that works offline until 2099.",
			anchor, machineID, "reject", "verify", "", false))
	}

	// --- entitlements (docs/typed-entitlements.md §4.4) ---
	//
	// Six fixtures pinning the whole SDK contract, because the interesting
	// half of this feature is what an SDK does with input it does not like.
	// Every one of them is an *accept*: a malformed entitlement value must
	// never take a working product offline (§2.5).
	{
		// The pre-entitlements world, and the reason HasEntitlements exists.
		// An old token, or a seller who has set nothing: every key denies,
		// and the probe says so, so an application can keep its legacy
		// behaviour for one release while its installed base renews (§6.3).
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "entitlements_absent", "entitlements",
			"No ent claim at all. Every can() is false, every limit() misses, and has_entitlements is false -- the probe a seller branches on while their installed base renews.",
			anchor, machineID, "accept", "none", "", false).
			withEnt(false, nil))
	}
	{
		// The happy path: both kinds, and a false that is present rather
		// than absent. `beta_ui: false` and an unset key both deny, but only
		// the first is in the map -- a distinction a seller reading the map
		// directly can act on.
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
			hasEntitlements: true,
			entitlements: map[string]any{
				"export_pdf":   true,
				"beta_ui":      false,
				"max_projects": 25,
			},
		})
		fixtures = append(fixtures, mk(cs, tok, "entitlements_bool_and_int", "entitlements",
			"Happy path: one true boolean, one false boolean, one integer. can(\"export_pdf\") is true, can(\"beta_ui\") is false, limit(\"max_projects\") is 25.",
			anchor, machineID, "accept", "none", "", false).
			withEnt(true, map[string]any{
				"export_pdf":   true,
				"beta_ui":      false,
				"max_projects": 25,
			}))
	}
	{
		// -1 is the unlimited sentinel and is returned *as-is*. An SDK must
		// not translate it to a maximum, to null, or to an absent key: the
		// caller compares against the exported UNLIMITED constant (§1.2).
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
			hasEntitlements: true,
			entitlements: map[string]any{
				"max_seats":    -1,
				"max_projects": 25,
			},
		})
		fixtures = append(fixtures, mk(cs, tok, "entitlements_unlimited", "entitlements",
			"The unlimited sentinel. limit(\"max_seats\") must return -1 exactly, not a maximum and not a miss; callers compare it against the SDK's UNLIMITED constant.",
			anchor, machineID, "accept", "none", "", false).
			withEnt(true, map[string]any{
				"max_seats":    -1,
				"max_projects": 25,
			}))
	}
	{
		// Every unrepresentable shape JSON can produce, in one token. Each
		// bad entry vanishes; the good one survives; the licence still
		// accepts. Rejecting the token instead would take a shipped product
		// offline over a data-entry mistake on a machine nobody can reach
		// (§2.5).
		//
		// 1.5 is here for the float rule specifically: a *fractional* number
		// is dropped, while a whole-valued one (25.0) is an integer, because
		// Go's and JavaScript's JSON parsers cannot tell 25 from 25.0 and a
		// rule they cannot implement is not a rule.
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
			hasEntitlements: true,
			entitlements: map[string]any{
				"export_pdf":   true,
				"max_projects": 25,
				"tier":         "pro",
				"ratio":        1.5,
				"nested":       map[string]any{"a": true},
				"listy":        []any{1, 2},
				"nulled":       nil,
			},
		})
		fixtures = append(fixtures, mk(cs, tok, "entitlements_malformed_value_dropped", "entitlements",
			"A string, a fractional number, a nested object, an array and a null alongside two good values. Each unrepresentable entry is dropped, the two good ones survive, and the licence still verifies and validates.",
			anchor, machineID, "accept", "none", "", false).
			withEnt(true, map[string]any{
				"export_pdf":   true,
				"max_projects": 25,
			}))
	}
	{
		// No coercion across kinds (§4.3 rule 3). seat_count is 0, which is
		// falsy in three of the five languages, and is_pro is a boolean,
		// which is 1-or-0 in two of them. Both must miss rather than
		// convert: this is the exact case that would split five
		// implementations quietly.
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
			hasEntitlements: true,
			entitlements: map[string]any{
				"is_pro":     true,
				"seat_count": 0,
			},
		})
		fixtures = append(fixtures, mk(cs, tok, "entitlements_type_mismatch", "entitlements",
			"can() on an integer key and limit() on a boolean key must both miss. seat_count is 0 (falsy in most languages) and is_pro is a boolean (1-or-0 in some); neither may coerce.",
			anchor, machineID, "accept", "none", "", false).
			withEnt(true, map[string]any{
				"is_pro":     true,
				"seat_count": 0,
			}))
	}
	{
		// "ent": {} behaves identically to an absent claim for can() and
		// limit(), and differs from it in exactly one observable: the
		// presence probe. That is the whole reason the probe is a separate
		// boolean rather than a len(map) check.
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
			hasEntitlements: true,
		})
		fixtures = append(fixtures, mk(cs, tok, "entitlements_empty_object", "entitlements",
			"An empty ent claim. Identical to entitlements_absent for every can()/limit(), and distinguishable from it only by has_entitlements, which is true here.",
			anchor, machineID, "accept", "none", "", false).
			withEnt(true, nil))
	}

	// --- renewal_failed: in_grace_period needs the flag as well as the age ---
	// Each token has a 7-day grace window, so only the flag and the age vary.
	{
		week := 7 * 24 * time.Hour
		renewalCase := func(name, description string, age time.Duration, failed bool, expect, reason string) fixture {
			cs := buildStandardChain()
			tok := signActivation(cs, activationOpts{
				iat: anchor.Add(-age), exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(week / time.Second),
				ltype: "expiring", machineID: machineID,
			})
			return mk(cs, tok, name, "renewal_failed", description,
				anchor, machineID, expect, mapStage(expect), reason, false).
				withRenewalFailed(failed)
		}
		fixtures = append(fixtures,
			renewalCase("renewal_not_failed_2h_old",
				"Issued 2h ago, past the 60-minute renewal marker, but no renewal attempt has failed: accepted, and not in the grace period.",
				2*time.Hour, false, "accept", ""),
			renewalCase("renewal_failed_under_60min",
				"Issued 30 minutes ago with a failed renewal flagged: the token is too young to be renewed, so not in the grace period.",
				30*time.Minute, true, "accept", ""),
			renewalCase("renewal_failed_exactly_60min",
				"Issued exactly 60 minutes ago with a failed renewal flagged: the age bound is strict (> 60 minutes), so not in the grace period.",
				60*time.Minute, true, "accept", ""),
			renewalCase("renewal_failed_past_grace_deadline",
				"Issued 8 days ago against a 7-day grace window with a failed renewal flagged: the flag does not extend the deadline, rejected as grace_expired.",
				8*24*time.Hour, true, "reject", "grace_expired"),
		)
	}

	// Write fixtures + manifest.
	var manifest []map[string]string
	written := 0
	for _, f := range fixtures {
		// The manifest lists every fixture regardless of -only, so a
		// filtered run never leaves a name out of the index.
		manifest = append(manifest, map[string]string{
			"name": f.Name, "category": f.Category, "expect": f.Expect,
			"expect_stage": f.ExpectStage, "expect_reason": f.ExpectReason,
		})
		if *only != "" && !strings.Contains(f.Name, *only) {
			continue
		}
		data, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			panic(err)
		}
		path := filepath.Join(outDir, f.Name+".json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			panic(err)
		}
		written++
	}
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), manifestData, 0o644); err != nil {
		panic(err)
	}

	fmt.Printf("wrote %d of %d fixtures + manifest.json to %s\n", written, len(fixtures), outDir)

	for name, build := range map[string]func() any{
		"anchors.json":     buildAnchors,
		"cache_files.json": buildCacheFiles,
	} {
		if *only != "" && !strings.Contains(name, *only) {
			continue
		}
		writeJSON(filepath.Join(outDir, "..", name), build())
		fmt.Printf("wrote %s\n", name)
	}
}

func writeJSON(path string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		panic(err)
	}
}

type anchorCase struct {
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	Now                 time.Time `json:"now"`
	MasterPublicKeysHex []string  `json:"master_public_keys_hex"`
	MachineID           string    `json:"machine_id"`
	Token               string    `json:"token"`
	Chain               struct {
		Submaster string `json:"submaster"`
		Project   string `json:"project"`
		Daily     string `json:"daily"`
	} `json:"chain"`
	Expect      string `json:"expect"`
	ExpectStage string `json:"expect_stage"`
}

// buildAnchors pins the any-of-several-roots rule: an SDK embeds a list of
// master keys and accepts a submaster cert that any one of them signed.
func buildAnchors() any {
	roots := []keyPair{newKeyPair(), newKeyPair(), newKeyPair()}
	trusted := []string{hexPub(roots[0]), hexPub(roots[1]), hexPub(roots[2])}

	mkCase := func(name, description string, signer keyPair, expect, stage string) anchorCase {
		cs := buildChainUnder(signer, anchor.AddDate(0, 0, -60), anchor.AddDate(0, 0, 60))
		c := anchorCase{
			Name: name, Description: description, Now: anchor,
			MasterPublicKeysHex: trusted, MachineID: machineID,
			Token: signActivation(cs, activationOpts{
				iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
				ltype: "expiring", machineID: machineID,
			}),
			Expect: expect, ExpectStage: stage,
		}
		c.Chain.Submaster, c.Chain.Project, c.Chain.Daily = cs.submasterCert, cs.projectCert, cs.dailyCert
		return c
	}

	return map[string]any{
		"description": "The submaster cert is accepted when any one of the trusted master keys signed it. Run each case through the SDK's list-taking verify with every key in master_public_keys_hex, then validate with machine_id, both at now. expect and expect_stage mean what they mean in vectors/.",
		"cases": []anchorCase{
			mkCase("anchor_first", "Signed by the first trusted root.", roots[0], "accept", "none"),
			mkCase("anchor_middle", "Signed by the middle trusted root: a loop that stops after the first key rejects it.", roots[1], "accept", "none"),
			mkCase("anchor_last", "Signed by the last trusted root: a loop that keeps only the first or the last error, rather than stopping at the first success, still has to accept.", roots[2], "accept", "none"),
			mkCase("anchor_outside", "Signed by a root that is not in the list.", newKeyPair(), "reject", "verify"),
		},
	}
}

// buildCacheFiles pins what an SDK does with a cached token file it cannot
// use. Every case must come out as "not activated", never as a crash or an
// exception the SDK does not otherwise raise.
func buildCacheFiles() any {
	cs := buildStandardChain()
	tok := signActivation(cs, activationOpts{
		iat: anchor, exp: anchor.AddDate(0, 1, 0), graceSeconds: int64(7 * 24 * time.Hour / time.Second),
		ltype: "expiring", machineID: machineID,
	})
	obj := func(fields string) string { return "{" + fields + "}" }
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	certs := func(token, sub, proj, daily string, upper bool) string {
		k := func(s string) string {
			if upper {
				return q(strings.ToUpper(s[:1]) + s[1:])
			}
			return q(s)
		}
		return obj(k("timestamp") + ":1700000000," + k("token") + ":" + token + "," +
			k("submaster") + ":" + sub + "," + k("project") + ":" + proj + "," + k("daily") + ":" + daily)
	}

	type cacheCase struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Contents    string `json:"contents"`
	}
	var cases []cacheCase
	add := func(name, description, contents string) {
		cases = append(cases, cacheCase{name, description, contents})
	}
	add("empty", "A zero-byte file.", "")
	add("legacy_timestamp_token", "The timestamp:token format: a token with no chain.", "1700000000:"+tok)
	add("json_null", "The JSON literal null.", "null")
	add("json_array", "A JSON array.", "[]")
	add("json_string", "A JSON string.", q(tok))
	add("json_number", "A JSON number.", "1700000000")
	add("truncated", "A write cut off part-way through the token.", `{"token":`+q(tok)[:40])
	for _, upper := range []bool{false, true} {
		s := "lower"
		if upper {
			s = "upper"
		}
		tk := "token"
		if upper {
			tk = "Token"
		}
		add("token_only_"+s, "A valid token and no chain fields.", obj(q(tk)+":"+q(tok)))
		add("null_chain_"+s, "A valid token with every chain field null.", certs(q(tok), "null", "null", "null", upper))
		add("number_chain_"+s, "A valid token with every chain field a number.", certs(q(tok), "1", "2", "3", upper))
		add("empty_chain_"+s, "A valid token with every chain field an empty string.", certs(q(tok), `""`, `""`, `""`, upper))
		add("object_chain_"+s, "A valid token with every chain field an object.", certs(q(tok), "{}", "{}", "{}", upper))
		add("null_token_"+s, "A null token beside a complete chain.", certs("null", q(cs.submasterCert), q(cs.projectCert), q(cs.dailyCert), upper))
		add("number_token_"+s, "A numeric token beside a complete chain.", certs("42", q(cs.submasterCert), q(cs.projectCert), q(cs.dailyCert), upper))
	}

	return map[string]any{
		"description":            "Cached token files an SDK cannot use. Write contents byte for byte to the file the SDK loads its cache from, load it, and if the loader yields a token and chain, verify them with master_public_keys_hex at now. Every case must end as not activated: the loader yields nothing, or verify rejects with the SDK's ordinary verify error. A crash, a panic or any other exception fails the case. Each shape appears with lowercase and with capitalised field names because the SDKs do not agree on which their own cache writes.",
		"now":                    anchor,
		"master_public_keys_hex": []string{hexPub(cs.master)},
		"machine_id":             machineID,
		"cases":                  cases,
	}
}

func mapStage(expect string) string {
	if expect == "accept" {
		return "none"
	}
	return "validate"
}

func mk(cs chainSet, token, name, category, description string, now time.Time, mid, expect, stage, reason string, inGrace bool) fixture {
	f := fixture{
		Name: name, Category: category, Description: description, Now: now,
		MasterPublicKeyHex: hexPub(cs.master),
		MachineID:          mid,
		Token:              token,
		Expect:             expect, ExpectStage: stage, ExpectReason: reason,
		ExpectInGrace:         inGrace,
		ExpectHasEntitlements: false,
		ExpectEntitlements:    map[string]any{},
	}
	f.Chain.Submaster = cs.submasterCert
	f.Chain.Project = cs.projectCert
	f.Chain.Daily = cs.dailyCert
	return f
}

// flipBitInPayload flips the low bit of the first byte of the base64url
// payload segment, guaranteeing the decoded JSON (or the raw bytes, if the
// flip lands on padding-adjacent bits) no longer matches what was signed.
func flipBitInPayload(token string) string {
	parts := splitJWT(token)
	payload := []byte(parts[1])
	payload[0] ^= 0x01
	return parts[0] + "." + string(payload) + "." + parts[2]
}

// corruptSignature mutates the signature segment only, leaving header and
// payload byte-identical to a validly-signed token.
func corruptSignature(token string) string {
	parts := splitJWT(token)
	sig := []byte(parts[2])
	sig[0] ^= 0x01
	if sig[0] == parts[2][0] { // ensure an actual change even if XOR was a no-op char
		sig[0] ^= 0x02
	}
	return parts[0] + "." + parts[1] + "." + string(sig)
}

func splitJWT(token string) [3]string {
	var out [3]string
	start := 0
	part := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			out[part] = token[start:i]
			part++
			start = i + 1
		}
	}
	out[part] = token[start:]
	return out
}
