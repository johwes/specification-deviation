// Command central is the M2 central store + ratification dashboard + drift
// detector -- the demo half of the PoC. Discovery events arrive from
// cmd/sensor daemons; a human ratifies proposals at /; ratified decisions
// are a git-backed store; a workload with a ratified baseline that
// contacts a net-new endpoint produces a spec_deviation signal, and
// raw-socket creation always produces an invariant_violation signal,
// regardless of ratification state. Signals are a JSON-lines file (M2.9).
//
// Plain HTTP, no mTLS -- see docs/backlog.md's parking lot. This proves
// the detection thesis (does ratify-then-detect-drift actually work), not
// hardening of the tool.
package main

import (
	"embed"
	"flag"
	"html/template"
	"log/slog"
	"net/http"
	"os"
)

//go:embed templates/index.html
var templatesFS embed.FS

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	decisionsPath := flag.String("decisions", "./data/decisions", "path to the git-backed decision store")
	signalsPath := flag.String("signals", "./data/signals.jsonl", "path to the signal-stream file sink")
	seedsPath := flag.String("seeds", "./data/seeds.yaml", "path to the static seeds file (optional)")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	tmpl, err := template.ParseFS(templatesFS, "templates/index.html")
	if err != nil {
		slog.Error("parse template failed", "error", err)
		os.Exit(1)
	}

	decisions, err := newDecisionStore(*decisionsPath)
	if err != nil {
		slog.Error("open decision store failed", "error", err)
		os.Exit(1)
	}

	signals, err := newSignalSink(*signalsPath)
	if err != nil {
		slog.Error("open signal sink failed", "error", err)
		os.Exit(1)
	}

	seeds, err := loadSeeds(*seedsPath)
	if err != nil {
		slog.Error("load seeds failed", "error", err, "path", *seedsPath)
		os.Exit(1)
	}
	if len(seeds.seeds) > 0 {
		slog.Info("loaded seeds", "count", len(seeds.seeds), "path", *seedsPath)
	}

	store := newStoreWithSeeds(decisions, signals, seeds)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", indexHandler(tmpl, store, signals))
	mux.HandleFunc("POST /decide", decideHandler(decisions))
	mux.HandleFunc("POST /dismiss", dismissHandler(store))
	mux.HandleFunc("POST /dismiss-workload", dismissWorkloadHandler(store))
	mux.HandleFunc("POST /dismiss-all", dismissAllHandler(store))
	mux.HandleFunc("POST /events", eventsHandler(store))

	slog.Info("central listening", "addr", *addr, "decisions", *decisionsPath, "signals", *signalsPath, "seeds", *seedsPath)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		slog.Error("server exited", "error", err)
		os.Exit(1)
	}
}
