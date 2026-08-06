package governance

import "time"

type Disclosure struct {
	Vendor     string
	NotifiedAt time.Time
	DeadlineAt time.Time
	CVE        string
}

type DisclosureAction string

const (
	ActionNotifyVendor      DisclosureAction = "notify-vendor"
	ActionAwait             DisclosureAction = "await"
	ActionPublishOnDeadline DisclosureAction = "publish-on-deadline"
)

func (d Disclosure) NextAction(now time.Time) DisclosureAction {
	// the deadline dominates: a lapsed window publishes even if never notified
	if !d.DeadlineAt.IsZero() && !now.Before(d.DeadlineAt) {
		return ActionPublishOnDeadline
	}
	if d.Vendor == "" || d.NotifiedAt.IsZero() {
		return ActionNotifyVendor
	}
	return ActionAwait
}

func (d Disclosure) Notify(now time.Time) Disclosure {
	if !d.NotifiedAt.IsZero() { // first notice wins
		return d
	}
	d.NotifiedAt = now
	return d
}

func (d Disclosure) DeadlinePassed(now time.Time) bool {
	// a zero DeadlineAt is no deadline, never passed
	return !d.DeadlineAt.IsZero() && !now.Before(d.DeadlineAt)
}
