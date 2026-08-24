// Command throwaway-listener is the disposable test listener for the M1
// exit criterion ("two nodes streaming ... to a throwaway central
// listener; survive central outage"). Not part of the product -- M2 builds
// the real ingestion API. This just accepts POSTed event batches and
// counts them, so M1.6's buffering/reconnect behavior can be demonstrated
// end to end.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"sync/atomic"
)

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	flag.Parse()

	var received atomic.Uint64
	var batches atomic.Uint64

	http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var batch []json.RawMessage
		if err := json.Unmarshal(body, &batch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		total := received.Add(uint64(len(batch)))
		n := batches.Add(1)
		log.Printf("batch #%d: %d events (total: %d)", n, len(batch), total)
		w.WriteHeader(http.StatusAccepted)
	})

	log.Printf("throwaway central listener on %s (POST /events)", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
