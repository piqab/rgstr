package backup

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a standard 5-field cron expression (minute hour
// day-of-month month day-of-week), evaluated in UTC. Fields accept *, n,
// a-b, lists and steps (*/15, 1-5/2). As in cron, when both day fields are
// restricted a day matches either.
type Schedule struct {
	expr                       string
	min, hour, dom, month, dow uint64 // bit sets
	domStar, dowStar           bool
}

// ParseSchedule parses a cron expression.
func ParseSchedule(expr string) (*Schedule, error) {
	f := strings.Fields(expr)
	if len(f) != 5 {
		return nil, fmt.Errorf("schedule %q: want 5 fields (minute hour day month weekday)", expr)
	}
	s := &Schedule{expr: expr, domStar: f[2] == "*", dowStar: f[4] == "*"}
	var err error
	parse := func(field string, lo, hi int) uint64 {
		if err != nil {
			return 0
		}
		var bits uint64
		bits, err = parseField(field, lo, hi)
		return bits
	}
	s.min = parse(f[0], 0, 59)
	s.hour = parse(f[1], 0, 23)
	s.dom = parse(f[2], 1, 31)
	s.month = parse(f[3], 1, 12)
	s.dow = parse(f[4], 0, 7)
	if err != nil {
		return nil, fmt.Errorf("schedule %q: %w", expr, err)
	}
	if s.dow&(1<<7) != 0 { // 7 is Sunday too
		s.dow |= 1
	}
	return s, nil
}

func parseField(field string, lo, hi int) (uint64, error) {
	var bits uint64
	for _, part := range strings.Split(field, ",") {
		rng, stepStr, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepStr)
			if err != nil || n < 1 {
				return 0, fmt.Errorf("bad step %q", part)
			}
			step = n
		}
		a, b := lo, hi
		if rng != "*" {
			from, to, isRange := strings.Cut(rng, "-")
			var err error
			if a, err = strconv.Atoi(from); err != nil {
				return 0, fmt.Errorf("bad value %q", part)
			}
			b = a
			if isRange {
				if b, err = strconv.Atoi(to); err != nil {
					return 0, fmt.Errorf("bad range %q", part)
				}
			} else if hasStep {
				b = hi
			}
		}
		if a < lo || b > hi || a > b {
			return 0, fmt.Errorf("%q out of range %d-%d", part, lo, hi)
		}
		for i := a; i <= b; i += step {
			bits |= 1 << uint(i)
		}
	}
	return bits, nil
}

func (s *Schedule) String() string { return s.expr }

// Next returns the first matching minute after t.
func (s *Schedule) Next(t time.Time) time.Time {
	t = t.UTC().Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(5, 0, 0) // e.g. "0 0 30 2 *" never matches
	for t.Before(limit) {
		if s.month&(1<<uint(t.Month())) == 0 {
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC)
			continue
		}
		if !s.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, time.UTC)
			continue
		}
		if s.hour&(1<<uint(t.Hour())) == 0 {
			t = t.Truncate(time.Hour).Add(time.Hour)
			continue
		}
		if s.min&(1<<uint(t.Minute())) == 0 {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return time.Time{}
}

func (s *Schedule) dayMatches(t time.Time) bool {
	dom := s.dom&(1<<uint(t.Day())) != 0
	dow := s.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case s.domStar && s.dowStar:
		return true
	case s.domStar:
		return dow
	case s.dowStar:
		return dom
	}
	return dom || dow
}
