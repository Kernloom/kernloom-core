// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/kernloom/kernloom-core/internal/kliq/actionstate"
	kliqruntime "github.com/kernloom/kernloom-core/internal/kliq/runtime"
)

func serveStatusAPI(args []string) {
	fs := flag.NewFlagSet("kliq status-api", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath, "path to KLIQ local SQLite state")
	listen := fs.String("listen", "127.0.0.1:18090", "local HTTP listen address")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := validateLocalListenAddress(*listen); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, closeStore := stateStoreOrExit(*statePath)
	defer closeStore()
	server := &http.Server{
		Addr:    *listen,
		Handler: statusAPIHandler(store, *statePath),
	}
	logInfo("kliq_status_api_starting", "addr", *listen, "state", *statePath)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logError("kliq_status_api_failed", "error", err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func statusAPIHandler(store actionstate.Store, statePath string, registries ...kliqruntime.AdapterRuntimeRegistry) http.Handler {
	var registry kliqruntime.AdapterRuntimeRegistry
	if len(registries) > 0 {
		registry = registries[0]
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeAPIJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if _, err := store.LastBundle(r.Context()); err != nil {
			writeAPIJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
			return
		}
		writeAPIJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		snapshot, err := buildStatusSnapshot(r.Context(), store, statePath, registry)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, snapshot)
	})
	mux.HandleFunc("/bundle", func(w http.ResponseWriter, r *http.Request) {
		bundle, err := store.LastBundle(r.Context())
		if err != nil {
			writeAPIError(w, statusForStoreError(err), err)
			return
		}
		writeAPIJSON(w, http.StatusOK, bundleStatus(bundle))
	})
	mux.HandleFunc("/adapters", func(w http.ResponseWriter, r *http.Request) {
		leases, err := store.AllLeases(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, adapterStatusViews(leases, registry))
	})
	mux.HandleFunc("/runtime/actions", func(w http.ResponseWriter, r *http.Request) {
		leases, err := store.AllLeases(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, runtimeActionViews(leases))
	})
	mux.HandleFunc("/runtime/actions/", func(w http.ResponseWriter, r *http.Request) {
		actionID := strings.TrimPrefix(r.URL.Path, "/runtime/actions/")
		if actionID == "" {
			writeAPIJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_runtime_action_id"})
			return
		}
		leases, err := store.AllLeases(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		action, ok := findRuntimeAction(leases, actionID)
		if !ok {
			writeAPIJSON(w, http.StatusNotFound, map[string]string{"error": "runtime_action_not_found"})
			return
		}
		writeAPIJSON(w, http.StatusOK, action)
	})
	mux.HandleFunc("/audit/pending", func(w http.ResponseWriter, r *http.Request) {
		records, err := store.PendingAudits(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, auditRecordViews(records))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		snapshot, err := buildStatusSnapshot(r.Context(), store, statePath, registry)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "kernloom_kliq_runtime_actions %d\n", len(snapshot.RuntimeActions))
		fmt.Fprintf(w, "kernloom_kliq_pending_audit_records %d\n", snapshot.PendingAuditCount)
		for status, count := range snapshot.RuntimeCounts {
			fmt.Fprintf(w, "kernloom_kliq_runtime_actions_by_status{status=%q} %d\n", status, count)
		}
	})
	return withRequestLogging(mux)
}

func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logInfo("kliq_status_api_request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func validateLocalListenAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("status api listen host %q must be localhost or a loopback address", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("status api listen host %q must be loopback-only", host)
	}
	return nil
}

func writeAPIJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAPIError(w http.ResponseWriter, status int, err error) {
	writeAPIJSON(w, status, map[string]string{"error": err.Error()})
}

func statusForStoreError(err error) int {
	if errors.Is(err, actionstate.ErrNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

func snapshotForTests(store actionstate.Store) (statusSnapshot, error) {
	return buildStatusSnapshot(context.Background(), store, "test-state.db", nil)
}
