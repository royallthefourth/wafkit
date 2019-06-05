package wafkit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPathTraversalClean(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, `http://example.com/asdf`, strings.NewReader(``))
	err := PathTraversal(r)
	if err != nil {
		t.Error(`Expected no error`)
	}
}

func TestPathTraversalCleanHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, `http://example.com/asdf`, strings.NewReader(``))
	r.Header.Add(`Accept`, `../files`)
	err := PathTraversal(r)
	if err == nil {
		t.Error(`Expected error`)
	}
}
