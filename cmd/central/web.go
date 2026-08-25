// Review UI (M2.6) and ingestion endpoint (M2.1). Server-rendered
// html/template, plain HTML forms -- no JS framework, no build step,
// consistent with the rest of this PoC's "don't add tooling the question
// doesn't need" discipline.
package main

import (
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"
)

type proposalView struct {
	Endpoint       EndpointRef
	Port           uint16
	Protocol       string
	InstanceCount  int
	FirstSeen      string
	LastSeen       string
	Count          int
	DirectToIP     bool
	ShellInitiated bool
}

type groupView struct {
	FleetIdentity string
	Proposals     []proposalView
}

type pageData struct {
	Signals      []Signal
	Groups       []groupView
	TotalPending int
}

const timeFmt = "15:04:05"

func buildPage(store *Store, signals *SignalSink) pageData {
	grouped := store.PendingProposals()

	fleetIdentities := make([]string, 0, len(grouped))
	for fi := range grouped {
		fleetIdentities = append(fleetIdentities, fi)
	}
	sort.Strings(fleetIdentities)

	var groups []groupView
	total := 0
	for _, fi := range fleetIdentities {
		props := grouped[fi]
		sort.Slice(props, func(i, j int) bool { return props[i].Endpoint.Value < props[j].Endpoint.Value })
		views := make([]proposalView, len(props))
		for i, p := range props {
			views[i] = proposalView{
				Endpoint:       p.Endpoint,
				Port:           p.Port,
				Protocol:       p.Protocol,
				InstanceCount:  len(p.Instances),
				FirstSeen:      p.FirstSeen.Format(timeFmt),
				LastSeen:       p.LastSeen.Format(timeFmt),
				Count:          p.Count,
				DirectToIP:     p.DirectToIP,
				ShellInitiated: p.ShellInitiated,
			}
		}
		total += len(views)
		groups = append(groups, groupView{FleetIdentity: fi, Proposals: views})
	}

	return pageData{Signals: signals.Recent(), Groups: groups, TotalPending: total}
}

func indexHandler(tmpl *template.Template, store *Store, signals *SignalSink) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.Execute(w, buildPage(store, signals)); err != nil {
			slog.Error("render index failed", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func decideHandler(decisions *DecisionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		port, err := strconv.ParseUint(r.FormValue("port"), 10, 16)
		if err != nil {
			http.Error(w, "bad port: "+err.Error(), http.StatusBadRequest)
			return
		}
		decidedBy := r.FormValue("decided_by")
		if decidedBy == "" {
			decidedBy = "unknown"
		}

		d := Decision{
			FleetIdentity: r.FormValue("fleet_identity"),
			Endpoint: EndpointRef{
				Type:  r.FormValue("endpoint_type"),
				Value: r.FormValue("endpoint_value"),
			},
			Port:      uint16(port),
			Protocol:  r.FormValue("protocol"),
			Decision:  r.FormValue("decision"),
			Owner:     r.FormValue("owner"),
			DecidedBy: decidedBy,
			DecidedAt: time.Now().UTC().Format(time.RFC3339),
			Source:    "learned",
		}
		if d.Decision != "allow" && d.Decision != "deny" {
			http.Error(w, "decision must be allow or deny", http.StatusBadRequest)
			return
		}

		if err := decisions.Ratify(d); err != nil {
			slog.Error("ratify failed", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// dismissHandler, dismissWorkloadHandler, and dismissAllHandler are
// housekeeping, not ratification -- see the comment on Store.Dismiss.
func dismissHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		port, err := strconv.ParseUint(r.FormValue("port"), 10, 16)
		if err != nil {
			http.Error(w, "bad port: "+err.Error(), http.StatusBadRequest)
			return
		}
		store.Dismiss(r.FormValue("fleet_identity"), r.FormValue("endpoint_value"), uint16(port), r.FormValue("protocol"))
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func dismissWorkloadHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		store.DismissWorkload(r.FormValue("fleet_identity"))
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func dismissAllHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store.DismissAll()
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func eventsHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var events []RawEvent
		if err := json.Unmarshal(body, &events); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		store.Ingest(events)
		w.WriteHeader(http.StatusAccepted)
	}
}
