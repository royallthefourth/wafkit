package wafkit

import "net/http"

type httpFilter func(http.HandlerFunc) http.HandlerFunc

// see here for prior art:
// https://www.modsecurity.org/CRS/Documentation/rules.html
// https://github.com/SpiderLabs/owasp-modsecurity-crs/tree/v3.2/dev/rules
