package criterion

import (
	"bytes"
	"io/ioutil"
	"net/http"
)

func AllButReferrer(r *http.Request, filter func(string) error) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	err = filter(string(body))
	if err != nil {
		return err
	}

	err = filter(r.URL.RawPath)
	if err != nil {
		return err
	}

	for header, vals := range r.Header {
		err = filter(header)
		if err != nil {
			return err
		}

		if header != `Referrer` {
			for _, val := range vals {
				err = filter(val)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}
