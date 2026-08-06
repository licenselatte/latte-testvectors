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
	"fmt"
	"os"
	"path/filepath"
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
	master := newKeyPair()
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
		"iat": unixT(anchor.AddDate(0, 0, -60)),
		"exp": unixT(anchor.AddDate(0, 0, 60)),
		"dpk": hexPub(daily),
	})

	return chainSet{
		master: master, submaster: submaster, project: project, daily: daily,
		submasterCert: submasterCert, projectCert: projectCert, dailyCert: dailyCert,
	}
}

// buildNarrowChain mints a daily cert with a tight +/-1 day validity window,
// used by the clock-skew fixtures where we need the verifier's "now" to
// fall outside the daily cert's own iat/exp on purpose.
func buildNarrowChain() chainSet {
	master := newKeyPair()
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
		"iat": unixT(anchor.AddDate(0, 0, -1)),
		"exp": unixT(anchor.AddDate(0, 0, 1)),
		"dpk": hexPub(daily),
	})

	return chainSet{
		master: master, submaster: submaster, project: project, daily: daily,
		submasterCert: submasterCert, projectCert: projectCert, dailyCert: dailyCert,
	}
}

const (
	projectID  = "proj_11111111-1111-1111-1111-111111111111"
	licenseKey = "AHAK85T628WZ639CMVHF8TNDDX260Z"
	activationID = "act_22222222-2222-2222-2222-222222222222"
	machineID  = "test-machine-001"
)

type activationOpts struct {
	iat, exp time.Time
	graceSeconds int64
	ltype string
	machineID string
	metadata map[string]string
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
		"grc":   o.graceSeconds,
	}
	if o.metadata != nil {
		claims["pmd"] = o.metadata
	}
	return sign(cs.daily.priv, claims)
}

// fixture is the canonical, language-agnostic test-vector shape documented
// in SPEC.md section 2.1.
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

	// Expect describes the required outcome. See ../README.md for the
	// full taxonomy every SDK's fixture runner must implement.
	Expect           string `json:"expect"`            // "accept" | "reject"
	ExpectStage      string `json:"expect_stage"`      // "none" | "verify" | "validate"
	ExpectReason     string `json:"expect_reason"`     // see README taxonomy; "" when ExpectStage == "verify" or "none" and accepted
	ExpectInGrace    bool   `json:"expect_in_grace_period"`
}

func main() {
	outDir := "../vectors"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
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
			anchor, machineID, "accept", "none", "", true))
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

	// --- perpetual_fixed bonus coverage ---
	{
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
			graceSeconds: int64(90 * 24 * time.Hour / time.Second), ltype: "perpetual_fixed", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "perpetual_fixed_valid", "valid_license",
			"perpetual_fixed license: grc must still be > 0 (validate.Validate checks this unconditionally before branching on LicenseType), but once past that precondition, perpetual_fixed skips the grace-deadline check entirely and only enforces hard expiry.",
			anchor, machineID, "accept", "none", "", false))
	}
	{
		cs := buildStandardChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor.AddDate(0, 0, -30), exp: anchor.AddDate(0, 0, -1),
			graceSeconds: int64(90 * 24 * time.Hour / time.Second), ltype: "perpetual_fixed", machineID: machineID,
		})
		fixtures = append(fixtures, mk(cs, tok, "perpetual_fixed_expired", "past_grace_period",
			"perpetual_fixed license whose exp has already passed; must hard-fail on ExpiresAt even though this type normally skips the grace-deadline check.",
			anchor, machineID, "reject", "validate", "hard_expired", false))
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
		// Verifier's clock is ahead of the daily cert's own exp.
		cs := buildNarrowChain()
		tok := signActivation(cs, activationOpts{
			iat: anchor, exp: anchor.Add(12 * time.Hour), graceSeconds: int64(6 * time.Hour / time.Second),
			ltype: "expiring", machineID: machineID,
		})
		now := anchor.AddDate(0, 0, 2) // after daily cert's exp (anchor+1d)
		fixtures = append(fixtures, mk(cs, tok, "clock_skew_after_cert_validity", "clock_skew",
			"Verifying machine's clock is set after the daily cert's own exp; must hard-fail chain verification with zero leeway.",
			now, machineID, "reject", "verify", "verify_error", false))
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
		fixtures = append(fixtures, mkBoundary("grace_boundary_one_second_before", iat.Add(7*24*time.Hour).Add(-time.Second), "accept", "", true))
		fixtures = append(fixtures, mkBoundary("grace_boundary_one_second_after", iat.Add(7*24*time.Hour).Add(time.Second), "reject", "grace_expired", false))
	}

	// Write fixtures + manifest.
	var manifest []map[string]string
	for _, f := range fixtures {
		data, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			panic(err)
		}
		path := filepath.Join(outDir, f.Name+".json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			panic(err)
		}
		manifest = append(manifest, map[string]string{
			"name": f.Name, "category": f.Category, "expect": f.Expect,
			"expect_stage": f.ExpectStage, "expect_reason": f.ExpectReason,
		})
	}
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), manifestData, 0o644); err != nil {
		panic(err)
	}

	fmt.Printf("wrote %d fixtures + manifest.json to %s\n", len(fixtures), outDir)
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
		ExpectInGrace: inGrace,
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
