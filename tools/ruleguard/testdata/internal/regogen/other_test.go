package regogen

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func upload() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func get() *http.Response { return &http.Response{StatusCode: http.StatusOK} }

func TestDiscarded(t *testing.T) {
	upload() // want `the response of upload is dropped`
	get()    // want `the response of get is dropped`
	if rec := upload(); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	_ = Record{State: "VALUE"}
}
