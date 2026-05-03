package orders

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/http-server/m/http"
)

// Register wires the orders endpoints onto mux:
//
//	POST /orders        — create
//	GET  /orders        — list
//	GET  /orders/{id}   — fetch one
//
// Routing is handler-side because our ServeMux dispatches purely on path,
// not method. "/orders" gets the exact-match handler (POST + list);
// "/orders/" picks up everything underneath for by-id lookups.
func Register(mux *http.ServeMux, store *Store) {
	mux.RegisterHandler("/orders", func(req *http.Request, w *http.ResponseWriter) {
		switch req.Method {
		case "POST":
			handleCreate(store, req, w)
		case "GET":
			handleList(store, w)
		default:
			writeError(w, 405, "method not allowed")
		}
	})

	mux.RegisterHandler("/orders/", func(req *http.Request, w *http.ResponseWriter) {
		if req.Method != "GET" {
			writeError(w, 405, "method not allowed")
			return
		}
		handleGet(store, req, w)
	})
}

type createRequest struct {
	Customer   string `json:"customer"`
	Item       string `json:"item"`
	Quantity   int    `json:"quantity"`
	PriceCents int    `json:"price_cents"`
}

func handleCreate(store *Store, req *http.Request, w *http.ResponseWriter) {
	var in createRequest
	if err := json.Unmarshal(req.Body, &in); err != nil {
		writeError(w, 400, "invalid JSON: "+err.Error())
		return
	}
	if in.Customer == "" || in.Item == "" || in.Quantity <= 0 || in.PriceCents < 0 {
		writeError(w, 400, "customer, item required; quantity > 0; price_cents >= 0")
		return
	}
	o, err := store.Create(Order{
		Customer:   in.Customer,
		Item:       in.Item,
		Quantity:   in.Quantity,
		PriceCents: in.PriceCents,
	})
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, o)
}

func handleList(store *Store, w *http.ResponseWriter) {
	orders, err := store.List()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if orders == nil {
		// Render an empty array rather than null — easier on clients.
		orders = []Order{}
	}
	writeJSON(w, 200, orders)
}

func handleGet(store *Store, req *http.Request, w *http.ResponseWriter) {
	idStr := strings.TrimPrefix(req.Path, "/orders/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "invalid id")
		return
	}
	o, err := store.Get(id)
	if errors.Is(err, ErrNotFound) {
		writeError(w, 404, "order not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, o)
}

func writeJSON(w *http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Headers["Content-Type"] = "application/json"
	w.WriteHeader(status)
	w.Write(body)
}

func writeError(w *http.ResponseWriter, status int, msg string) {
	body, _ := json.Marshal(map[string]string{"error": msg})
	w.Headers["Content-Type"] = "application/json"
	w.WriteHeader(status)
	w.Write(body)
}
