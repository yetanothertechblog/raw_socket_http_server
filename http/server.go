package http

import (
	"errors"
	"fmt"
	"io"
)

// Serve reads one HTTP request from rw, dispatches it through mux, and writes
// the response. It does not close rw — the caller owns the connection
// lifetime. A clean io.EOF before any bytes are received is treated as the
// peer closing without sending a request and produces no response. Parser
// errors are turned into matching 4xx/5xx replies via WriteError.
//
// One request per call by design: we always send Connection: close, so the
// caller's loop is `accept → go Serve → close` rather than persisting the
// connection across requests.
func Serve(rw io.ReadWriter, mux *ServeMux) {
	req, err := ReadRequest(rw)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return
		}
		fmt.Printf("http: read error: %v\n", err)
		_ = WriteError(rw, err)
		return
	}

	resp := mux.Handle(req)
	if err := WriteResponse(rw, resp); err != nil {
		fmt.Printf("http: write error: %v\n", err)
	}
}
