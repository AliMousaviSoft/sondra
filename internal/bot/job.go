package bot

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Job is a running scan or monitor started from chat.
type Job struct {
	ID        int
	Kind      string // "scan" or "monitor"
	Domain    string
	Preset    string
	StartedAt time.Time
	cancel    context.CancelFunc
}

// jobs is a thread-safe registry of active jobs.
type jobs struct {
	mu   sync.Mutex
	m    map[int]*Job
	next int
}

func newJobs() *jobs { return &jobs{m: make(map[int]*Job)} }

// add registers a job and returns it plus a cancellable context derived from
// parent. The caller must call finish(id) when the job ends.
func (j *jobs) add(parent context.Context, kind, domain, preset string) (*Job, context.Context) {
	ctx, cancel := context.WithCancel(parent)
	j.mu.Lock()
	defer j.mu.Unlock()
	j.next++
	job := &Job{
		ID:        j.next,
		Kind:      kind,
		Domain:    domain,
		Preset:    preset,
		StartedAt: time.Now(),
		cancel:    cancel,
	}
	j.m[job.ID] = job
	return job, ctx
}

// addWithID registers a job under a specific id (used when resuming persisted
// jobs so /stop <id> stays stable across restarts) and advances the id counter
// past it so future add() calls never collide.
func (j *jobs) addWithID(parent context.Context, id int, kind, domain, preset string) (*Job, context.Context) {
	ctx, cancel := context.WithCancel(parent)
	j.mu.Lock()
	defer j.mu.Unlock()
	if id > j.next {
		j.next = id
	}
	job := &Job{
		ID:        id,
		Kind:      kind,
		Domain:    domain,
		Preset:    preset,
		StartedAt: time.Now(),
		cancel:    cancel,
	}
	j.m[id] = job
	return job, ctx
}

func (j *jobs) finish(id int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if job, ok := j.m[id]; ok {
		job.cancel()
		delete(j.m, id)
	}
}

// stop cancels a job by id. Returns false if no such job is running.
func (j *jobs) stop(id int) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	job, ok := j.m[id]
	if !ok {
		return false
	}
	job.cancel()
	return true
}

// stopAll cancels every active job and returns how many were cancelled.
func (j *jobs) stopAll() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	n := 0
	for _, job := range j.m {
		job.cancel()
		n++
	}
	return n
}

// list returns active jobs sorted by id.
func (j *jobs) list() []*Job {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]*Job, 0, len(j.m))
	for _, job := range j.m {
		out = append(out, job)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}

// render lists active jobs for a /status or /list reply in the transport's markup.
func (j *jobs) render(f formatter) string {
	list := j.list()
	if len(list) == 0 {
		return "No active jobs."
	}
	var body strings.Builder
	for _, job := range list {
		fmt.Fprintf(&body, "#%-3d %-7s %-24s %-7s %s\n",
			job.ID, job.Kind, job.Domain, job.Preset,
			time.Since(job.StartedAt).Round(time.Second))
	}
	return f.bold("Active jobs") + "\n" + f.block(strings.TrimRight(body.String(), "\n"))
}
