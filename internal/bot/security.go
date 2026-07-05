package bot

import (
	"regexp"
	"strings"
)

// domainRe matches a plain DNS hostname: labels of alphanumerics/hyphens, a TLD
// of 2+ letters, nothing else. Because bot input flows into exec'd recon tools,
// this is the injection gate — it rejects spaces, shell metacharacters, flags,
// URLs, and anything that isn't a bare domain.
var domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// validDomain reports whether d is a safe, well-formed domain to hand to the
// recon pipeline. It normalizes case and rejects anything oversized or malformed.
func validDomain(d string) bool {
	d = strings.TrimSpace(strings.ToLower(d))
	if l := len(d); l == 0 || l > 253 {
		return false
	}
	return domainRe.MatchString(d)
}

// validExcludes reports whether every exclude entry is itself a safe hostname.
func validExcludes(ex []string) bool {
	for _, e := range ex {
		if !validDomain(e) {
			return false
		}
	}
	return true
}
