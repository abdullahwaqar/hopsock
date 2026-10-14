package hopsock

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Stats tracks live and finished connections. Safe for concurrent use.
type Stats struct {
	nextID   atomic.Uint64
	total    atomic.Uint64
	failed   atomic.Uint64
	upDone   atomic.Int64 // bytes from closed conns
	downDone atomic.Int64

	mu   sync.Mutex
	live map[uint64]*ConnInfo
}

// ConnInfo is one proxied connection.
type ConnInfo struct {
	ID     uint64
	Client string
	Target string
	Start  time.Time
	Up     atomic.Int64 // client -> target
	Down   atomic.Int64 // target -> client
}

// ConnView is a copy of ConnInfo for display.
type ConnView struct {
	ID       uint64
	Client   string
	Target   string
	Start    time.Time
	Up, Down int64
}

// Snapshot is a point-in-time view of Stats.
type Snapshot struct {
	Active   []ConnView // oldest first
	Total    uint64
	Failed   uint64
	Up, Down int64 // all bytes, including live conns
}

func (s *Stats) open(client, target string) *ConnInfo {
	ci := &ConnInfo{ID: s.nextID.Add(1), Client: client, Target: target, Start: time.Now()}
	s.total.Add(1)
	s.mu.Lock()
	if s.live == nil {
		s.live = make(map[uint64]*ConnInfo)
	}
	s.live[ci.ID] = ci
	s.mu.Unlock()
	return ci
}

func (s *Stats) close(ci *ConnInfo) {
	s.mu.Lock()
	delete(s.live, ci.ID)
	s.upDone.Add(ci.Up.Load())
	s.downDone.Add(ci.Down.Load())
	s.mu.Unlock()
}

func (s *Stats) fail() { s.failed.Add(1) }

// Snapshot copies the current state.
func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	snap := Snapshot{
		Total:  s.total.Load(),
		Failed: s.failed.Load(),
		Up:     s.upDone.Load(),
		Down:   s.downDone.Load(),
	}
	for _, ci := range s.live {
		v := ConnView{ID: ci.ID, Client: ci.Client, Target: ci.Target, Start: ci.Start, Up: ci.Up.Load(), Down: ci.Down.Load()}
		snap.Up += v.Up
		snap.Down += v.Down
		snap.Active = append(snap.Active, v)
	}
	s.mu.Unlock()
	sort.Slice(snap.Active, func(i, j int) bool { return snap.Active[i].ID < snap.Active[j].ID })
	return snap
}
