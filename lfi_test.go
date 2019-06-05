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

func TestPathTraversalDirtyHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, `http://example.com/asdf`, strings.NewReader(``))
	r.Header.Add(`Accept`, `../files`)
	err := PathTraversal(r)
	if err == nil {
		t.Error(`Expected error`)
	}
}

func TestOsFileIncludeClean(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, `http://example.com/asdf`, strings.NewReader(``))
	err := OsFileInclude(r)
	if err != nil {
		t.Error(`Expected no error`)
	}
}

func TestOsFileIncludeDirtyHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, `http://example.com/asdf`, strings.NewReader(``))
	r.Header.Add(`Accept`, `php5/php.ini`)
	err := OsFileInclude(r)
	if err == nil {
		t.Error(`Expected error`)
	}
}
