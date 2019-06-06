package wafkit

import (
	"net/http"
	"regexp"
	"strings"
	wafkit "wafkit/internal"
	"wafkit/internal/criterion"
	"wafkit/internal/data"
)

type ErrPathTraversal struct{}

func (e ErrPathTraversal) Error() string {
	return `Detected path traversal`
}

type ErrOsFileInclude struct{}

func (e ErrOsFileInclude) Error() string {
	return `Detected OS file include`
}

// PathTraversal filters path traversal attempts.
// See https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.2/dev/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf#L30
func PathTraversal(r *http.Request) error {
	return criterion.AllButReferrer(r, detectPathTraversal)
}

const pathTraversal = `(?:\x5c|(?:%(?:c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|2(?:5(?:c(?:0%25af|1%259c)|2f|5c)|%46|f)|(?:(?:f(?:8%8)?0%8|e)0%80%a|bg%q)f|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|u(?:221[56]|002f|EFC8|F025)|1u|5c)|0x(?:2f|5c)|\/))(?:%(?:(?:f(?:(?:c%80|8)%8)?0%8|e)0%80%ae|2(?:(?:5(?:c0%25a|2))?e|%45)|u(?:(?:002|ff0)e|2024)|%32(?:%(?:%6|4)5|E)|c0(?:%[256aef]e|\.))|\.(?:%0[01]|\?)?|\?\.?|0x2e){2}(?:\x5c|(?:%(?:c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|2(?:5(?:c(?:0%25af|1%259c)|2f|5c)|%46|f)|(?:(?:f(?:8%8)?0%8|e)0%80%a|bg%q)f|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|u(?:221[56]|002f|EFC8|F025)|1u|5c)|0x(?:2f|5c)|\/))`

var pathTraversalExp *regexp.Regexp

func detectPathTraversal(input string) error {
	if pathTraversalExp == nil {
		pathTraversalExp = regexp.MustCompile(pathTraversal)
	}

	if pathTraversalExp.MatchString(input) || // encoded traversal attempts
		strings.Contains(input, `..\`) || // plaintext traversal attempts
		strings.Contains(input, `../`) {
		return ErrPathTraversal{}
	}

	return nil
}

// OsFileInclude filters attempts to access OS files.
// See https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.2/dev/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf#L70
func OsFileInclude(r *http.Request) error {
	return criterion.AllButReferrer(r, detectOsFileIncude)
}

var osFileSearch *wafkit.TrieNode

func detectOsFileIncude(input string) error {
	if osFileSearch == nil {
		osFileSearch = &wafkit.TrieNode{}
		for _, word := range data.OsFiles {
			osFileSearch.Insert(word)
		}
	}

	if osFileSearch.Contains(input) {
		return ErrOsFileInclude{}
	}

	return nil
}
