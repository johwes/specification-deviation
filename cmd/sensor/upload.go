// Local event buffer + central upload (M1.6). The bounded buffer plus
// periodic retry is the thing this milestone actually demonstrates:
// "central is a convenience, never a dependency"
// (architecture-specification.md design principle 3) -- kill central for
// the whole buffer window and no event is lost; restart it and the backlog
// drains.
//
// Deliberately plain HTTP, not mTLS -- see the parking lot in
// docs/backlog.md for why. central_url is optional; if unset, events go to
// stdout only (the M0/M1.1-M1.5 behavior), matching "zero required setup."
//
// "Local decision cache" from the M1.6 story has no content yet: there are
// no ratified decisions to cache until M2 builds the ratification workflow.
// Deferred until there's something real to cache.
package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	maxUploadBufferEvents = 200000 // generous headroom over "10 min, no loss" at realistic event rates
	uploadInterval        = 2 * time.Second
	uploadTimeout         = 5 * time.Second
)

type uploader struct {
	url    string
	client *http.Client

	mu  sync.Mutex
	buf [][]byte
}

func newUploader(url string) *uploader {
	return &uploader{
		url:    url,
		client: &http.Client{Timeout: uploadTimeout},
	}
}

// enqueue never blocks and never touches the network -- called from the hot
// event-processing loop in run(). A full buffer drops the oldest event to
// make room; central being down must never stall live event processing.
func (u *uploader) enqueue(data []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.buf) >= maxUploadBufferEvents {
		u.buf = u.buf[1:]
	}
	u.buf = append(u.buf, data)
}

// run periodically attempts to drain the buffer to central until ctx is
// done. A failed send leaves the buffer untouched, retried next tick, with
// newly-enqueued events accumulating (bounded) in the meantime.
func (u *uploader) run(ctx context.Context) {
	ticker := time.NewTicker(uploadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.drain(ctx)
		}
	}
}

func (u *uploader) drain(ctx context.Context) {
	u.mu.Lock()
	if len(u.buf) == 0 {
		u.mu.Unlock()
		return
	}
	// Copy the snapshot rather than alias u.buf's backing array: enqueue()
	// can append or evict concurrently once we unlock, and appending in
	// place could otherwise race with the read below.
	batch := make([][]byte, len(u.buf))
	copy(batch, u.buf)
	u.mu.Unlock()

	body := make([]byte, 0, 1024*len(batch))
	body = append(body, '[')
	body = append(body, bytes.Join(batch, []byte(","))...)
	body = append(body, ']')

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(body))
	if err != nil {
		slog.Error("upload request build failed", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := u.client.Do(req)
	if err != nil {
		slog.Warn("upload failed, will retry", "error", err, "buffered", len(batch))
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		slog.Warn("upload rejected, will retry", "status", resp.StatusCode, "buffered", len(batch))
		return
	}

	u.mu.Lock()
	// Remove exactly what we sent. If overflow eviction shifted the front
	// concurrently while the request was in flight, this can be slightly
	// imprecise (accepted spike-grade tradeoff -- full exactly-once
	// accounting needs per-event acks, out of scope for M1.6).
	if len(u.buf) >= len(batch) {
		u.buf = u.buf[len(batch):]
	} else {
		u.buf = u.buf[:0]
	}
	u.mu.Unlock()
	slog.Info("uploaded events to central", "count", len(batch))
}
