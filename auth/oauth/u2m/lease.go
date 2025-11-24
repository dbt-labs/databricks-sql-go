package u2m

import (
	"bytes"
	entropy "crypto/rand"
	"encoding/base64"
	"fmt"

	// "github.com/timandy/routine"
	"io"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	gracePeriod     = 12 * time.Millisecond
	minPollInterval = 200 * time.Millisecond
	maxPollInterval = 5 * time.Second

	MinRequestedTTL              = 400 * time.Millisecond
	MinLeaseOperationTimeout     = 3 * time.Second
	DefaultLeaseOperationTimeout = 30 * time.Second
)

// Helper functions for min/max (Go < 1.21 compatibility)
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func max(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// Leases [1] are acquired from a shared `LeaseHandler` instance.
//
// [1] https://en.wikipedia.org/wiki/Lease_(computer_science)
type Lease struct {
	id      string
	expiry  time.Time // cached lease expiry
	handler *LeaseHandler
}

// Ensure the lease will be valid for at least the given TTL. Users should
// call this periodically to keep the lease alive (e.g. every TTL/2 interval).
func (lease *Lease) Renew(ttl time.Duration) error {
	newExpiry, err := lease.handler.renew(&lease.id, ttl, lease.expiry)
	if err == nil {
		lease.expiry = newExpiry
	} else {
		lease.expiry = time.Time{}
	}
	return err
}

// Makes an effort to release the given leaseId to help other processes acquire
// it sooner as they won't have to wait for the lease to expire.
//
// An error is returned if the lease is not held by the current process, which
// can happen when the process is not ensuring continuous renewal of the lease
// or using TTLs that are too short.
func (lease *Lease) Release() error {
	expiry := lease.expiry
	lease.expiry = time.Time{}
	return lease.handler.release(&lease.id, expiry)
}

// File-based lease [1]. Leases are acquired through a shared [LeaseHandler]
// instance.
//
// [1] https://en.wikipedia.org/wiki/Lease_(computer_science)
type LeaseHandler struct {
	path          string // absolute path to the lease file
	dir           string // directory where the lease file is stored
	timeoutMillis int32  // atomic; how long to keep trying to acquire or renew a lease
}

func NewLeaseHandler(path string, timeout time.Duration) (*LeaseHandler, error) {
	abspath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("lease: %w", err)
	}
	dir := filepath.Dir(abspath)
	h := &LeaseHandler{path: abspath, dir: dir}
	h.SetTimeout(timeout)
	return h, nil
}

// Normalize timeout to atomic-friendly i32 and store atomically
// Clamp to prevent wraparound. Truncate to ms.
func (l *LeaseHandler) SetTimeout(d time.Duration) {
	if d < MinLeaseOperationTimeout {
		d = MinLeaseOperationTimeout
	}
	ms := d.Milliseconds()
	if ms > math.MaxInt32 {
		ms = math.MaxInt32
	}
	atomic.StoreInt32(&l.timeoutMillis, int32(ms))
}

func (l *LeaseHandler) getTimeout() time.Duration {
	ms := atomic.LoadInt32(&l.timeoutMillis)
	return time.Duration(ms) * time.Millisecond
}

func randomLeaseId() (string, error) {
	var b [16]byte
	if _, err := entropy.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// `wait(base, m, cap)` sleeps for a duration uniformly sampled from the
// [base, m] range and capped at `cap`.
//
// Jitter is used to avoid the Thundering Herd problem [1] in different lease
// operations.
//
// [1] https://en.wikipedia.org/wiki/Thundering_herd_problem
func wait(base, m, cap time.Duration) time.Duration {
	d := base
	m -= base
	if m > 0 {
		d += time.Duration(rand.Int63n(int64(m) + 1))
	}
	if d > 0 && cap > 0 {
		if d > cap {
			d = cap
		}
		// fmt.Fprintf(os.Stdout, "[%v] time.Sleep(%v)\n", routine.Goid(), d)
		time.Sleep(d)
		return d
	}
	return 0
}

// Atomically update the contents of the lease file with the given leaseId and expiry.
//
// The lease file is written to a temporary file first, and then the temporary
// file is atomically renamed to the lease file path. The Go runtime guarantees
// atomicity on POSIX systems and on Windows by using `MOVEFILE_REPLACE_EXISTING`.
//
// The lease file is written and then read back after a grace period to ensure
// that no other process has overwritten the lease file right after we wrote it.
// The grace period should be long enough to ensure processes can read the lease
// and determine they cannot acquire it.
func (l *LeaseHandler) write(leaseId *string, expiry time.Time) error {
	ctime := time.Now()
	f, err := os.CreateTemp(l.dir, "*.lease")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	expiry = expiry.Add(gracePeriod) // compensate for the wait after the write
	if _, err := fmt.Fprintf(f, "%s\r\n%d\r\n%d\r\n", *leaseId, ctime.UnixMilli(), expiry.UnixMilli()); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	err = os.Rename(f.Name(), l.path)
	if err != nil {
		return err
	}
	// fmt.Fprintf(os.Stdout, "[%v] WRITTEN: id='%s' ttl=%v elapsed=%s file=%s\n",
	// 	routine.Goid(), *leaseId, expiry.Sub(time.Now()), time.Since(ctime), l.path)
	data, err := l.read(gracePeriod-time.Since(ctime), 0, gracePeriod)
	if err != nil {
		return err
	}
	if data.leaseId != *leaseId {
		return fmt.Errorf("racy lease write: expected '%s', got '%s'", *leaseId, data.leaseId)
	}
	// fmt.Fprintf(os.Stdout, "[%v] WRITTEN+read: id='%s' ttl='%v' file=%s\n",
	// 	routine.Goid(), *leaseId, data.ttl(), l.path)
	return nil
}

func parseLeaseFile(f *os.File) *leaseData {
	buffer := make([]byte, 0, 128)
	var err error
	for {
		var n int
		n, err = f.Read(buffer[len(buffer):cap(buffer)])
		buffer = buffer[:len(buffer)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		}

		if len(buffer) >= cap(buffer) {
			return nil // lease file is too large (unexpected)
		}
	}
	if err != nil {
		return nil // error issuing reads on open lease file
	}
	parts := bytes.SplitN(buffer, []byte{'\r', '\n'}, 4)
	if len(parts) < 3 {
		return nil // corrupt lease file
	}
	leaseId := string(parts[0])
	ctimeMillis, parseErr1 := strconv.ParseInt(string(parts[1]), 10, 64)
	expiryMillis, parseErr2 := strconv.ParseInt(string(parts[2]), 10, 64)
	if parseErr1 != nil || parseErr2 != nil {
		return nil // corrupt lease file
	}
	return &leaseData{
		leaseId: leaseId,
		ctime:   time.UnixMilli(ctimeMillis),
		expiry:  time.UnixMilli(expiryMillis)}
}

// Read the current lease ID and expiry time from the lease file.
// [read] calls [wait(base, m, cap)] before reading the file so callers
// can conveniently add a delay before reading the lease file again.
func (l *LeaseHandler) read(base, m, cap time.Duration) (*leaseData, error) {
	wait(base, m, cap)

	noData := &leaseData{
		leaseId: "",
		ctime:   time.Time{},
		expiry:  time.Time{},
	}
	f, err := os.OpenFile(l.path, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			// fmt.Fprintf(os.Stdout, "[%v] read empty: file=%s\n", routine.Goid(), l.path)
			return noData, nil // no lease file
		}
		return noData, err // error opening the file
	}
	data := parseLeaseFile(f)
	if data == nil {
		// corrupt lease file, delete it
		_ = f.Close()
		_ = os.Remove(l.path)
		return noData, nil // as if it never existed
	}
	_ = f.Close()
	// fmt.Fprintf(os.Stdout, "[%v] read: id='%s' ttl=%v\n",
	// 	routine.Goid(), data.leaseId, data.ttl())
	return data, nil
}

// Adjust `base` and `m` for the next wait(base, m, cap) call.
func nextWait(base, m time.Duration) (time.Duration, time.Duration) {
	if m > math.MaxInt64/2 {
		m = math.MaxInt64
	}
	if m < minPollInterval {
		m = minPollInterval
	} else {
		m = m * 2
	}
	base = m / 2
	return base, m
}

func (l *LeaseHandler) Acquire(ttl time.Duration) (*Lease, error) {
	ttl = max(ttl, MinRequestedTTL)

	newLeaseId, err := randomLeaseId()
	if err != nil {
		return nil, fmt.Errorf("lease: %s: %w", l.path, err)
	}
	// fmt.Fprintf(os.Stdout, "[%v] Acquire('%s', %v)\n", routine.Goid(), newLeaseId, ttl)

	newExpiry := func() time.Time {
		return time.Now().Add(ttl).Add(gracePeriod)
	}

	base := time.Duration(0)
	m := gracePeriod
	deadline := time.Now().Add(l.getTimeout())
	for time.Now().Before(deadline) {
		data, err := l.read(base, m, min(deadline.Sub(time.Now())/2, maxPollInterval))
		base, m = nextWait(base, m)
		if err != nil {
			continue
		}
		// 1. empty lease file
		if data.leaseId == "" {
			expiry := newExpiry()
			err = l.write(&newLeaseId, expiry)
			if err != nil {
				continue
			}
			// fmt.Fprintf(os.Stdout, "[%v] ACQUIRED: id='%s' ttl=%v\n\n",
			// 	routine.Goid(), newLeaseId, expiry.Sub(time.Now()))
			return &Lease{id: newLeaseId, expiry: expiry, handler: l}, nil
		}
		now := time.Now()
		// 2. current lease is still valid
		if now.Before(data.expiry) {
			m = min(m, data.expiry.Sub(now))
			base = m / 2
			continue
		}
		// 3. existing lease is expired
		expiry := newExpiry()
		err = l.write(&newLeaseId, expiry)
		if err != nil {
			continue
		}
		// fmt.Fprintf(os.Stdout, "[%v] ACQUIRED: id='%s' ttl='%v'\n\n",
		// 	routine.Goid(), newLeaseId, expiry.Sub(time.Now()))
		return &Lease{id: newLeaseId, expiry: expiry, handler: l}, nil
	}

	return nil, fmt.Errorf("timed out trying to acquire lease after %s: %s", l.getTimeout(), l.path)
}

func (l *LeaseHandler) renew(leaseId *string, ttl time.Duration, currentExpiry time.Time) (time.Time, error) {
	// fmt.Fprintf(os.Stdout, "[%v] Renew('%s')\n", routine.Goid(), *leaseId)

	base := time.Duration(0)
	m := time.Duration(0)
	deadline := time.Now().Add(l.getTimeout())
	for time.Now().Before(deadline) {
		wait(base, m, min(deadline.Sub(time.Now())/2, maxPollInterval))
		base, m = nextWait(base, m)
		now := time.Now()
		// 1. check if the lease is still held
		held := now.Add(gracePeriod).Before(currentExpiry)
		if !held {
			return time.Time{}, fmt.Errorf("lease '%s' has expired: %s", *leaseId, l.path)
		}
		// // debug-only sanity check
		// if data, _ := l.read(0, 0, 0); !data.leaseIsHeld(leaseId, now) {
		// 	panic(fmt.Sprintf("lease '%s' is not held by this process: %s", *leaseId, l.path))
		// }
		// 2. check if the held lease needs to be renewed
		isNew := now.Add(ttl).Add(gracePeriod).Before(currentExpiry)
		if !isNew {
			newExpiry := now.Add(2 * ttl) // 2x the desired TTL if we are updating the lease
			err := l.write(leaseId, newExpiry)
			if err == nil {
				return newExpiry, nil
			}
			continue // retry on write error
		}
		return currentExpiry, nil
	}
	return time.Time{}, fmt.Errorf("timed out trying to renew lease: %s id='%s'", l.path, *leaseId)
}

func (handler *LeaseHandler) release(leaseId *string, currentExpiry time.Time) error {
	// fmt.Fprintf(os.Stdout, "[%v] Release('%s')\n", routine.Goid(), *leaseId)
	// // debug-only sanity check
	// if data, _ := handler.read(0, 0, 0); !data.leaseIsHeld(leaseId, time.Now()) {
	// 	panic(fmt.Sprintf("lease '%s' is not held by this process: %s", *leaseId, handler.path))
	// }
	if now := time.Now(); now.Before(currentExpiry) {
		if now.Add(gracePeriod).Before(currentExpiry) {
			_ = os.Remove(handler.path)
		}
		return nil
	}
	return fmt.Errorf("lease not held during release attempt: %s id='%s'", handler.path, *leaseId)
}

type leaseData struct {
	leaseId string
	ctime   time.Time // creation time of this version of the lease file
	expiry  time.Time // when the lease expires
}

func (data *leaseData) ttl() time.Duration {
	return data.expiry.Sub(time.Now())
}

func (data *leaseData) leaseIsHeld(leaseId *string, now time.Time) bool {
	return data.leaseId == *leaseId && now.Add(gracePeriod).Before(data.expiry)
}
