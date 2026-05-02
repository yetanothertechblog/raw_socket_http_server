package http

type Request struct {
	Method  string
	Path    string
	Headers map[string]string
	Body    []byte
}

type ResponseWriter struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

func (w *ResponseWriter) Write(data []byte) (int, error) {
	w.Body = append(w.Body, data...)
	return len(data), nil
}

func (w *ResponseWriter) WriteHeader(statusCode int) {
	w.StatusCode = statusCode
}

type HandlerFunc func(*Request, *ResponseWriter)

type ServeMux struct {
	routes map[string]HandlerFunc
}

func (mux *ServeMux) RegisterHandler(path string, handlerFunc HandlerFunc) {
	mux.routes[path] = handlerFunc
}

func (mux *ServeMux) Handle(req *Request) *ResponseWriter {
	w := &ResponseWriter{
		StatusCode: 200,
		Headers:    make(map[string]string),
	}
	handler, ok := mux.routes[req.Path]

	if !ok {
		w.StatusCode = 404
		w.Write([]byte("404 Not Found\n"))
		return w
	}

	handler(req, w)
	return w

}

var statusTexts = map[int]string{
	200: "OK",
	201: "Created",
	204: "No Content",
	301: "Moved Permanently",
	302: "Found",
	304: "Not Modified",
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	500: "Internal Server Error",
}
