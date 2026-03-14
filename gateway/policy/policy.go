package policy

import (
	"strings"
	"time"

	"github.com/isshaan-dhar/TunnelForge/db"
)

type DenialReason string

const (
	DenialOffHours       DenialReason = "off_hours"
	DenialResourceDenied DenialReason = "resource_denied"
	DenialNoPolicy       DenialReason = "no_policy"
)

type Result struct {
	Allowed bool
	Reason  DenialReason
}

func Evaluate(p *db.Policy, resource string, now time.Time) Result {
	if p == nil {
		return Result{Allowed: false, Reason: DenialNoPolicy}
	}

	hour := now.UTC().Hour()
	if hour < p.AllowedHoursStart || hour > p.AllowedHoursEnd {
		return Result{Allowed: false, Reason: DenialOffHours}
	}

	if len(p.AllowedResources) > 0 {
		allowed := false
		for _, res := range p.AllowedResources {
			if strings.HasPrefix(resource, res) {
				allowed = true
				break
			}
		}
		if !allowed {
			return Result{Allowed: false, Reason: DenialResourceDenied}
		}
	}

	return Result{Allowed: true}
}
