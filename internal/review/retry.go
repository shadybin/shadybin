package review

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// retryWaits are the pauses between tries of a download. The analysis downloads from
// servers shadybin does not run, and neither a review nor a seal check may turn on one
// dropped connection or one failed lookup.
var retryWaits = []time.Duration{5 * time.Second, 20 * time.Second}

// finalError is a failure that another try would only repeat: a package with the wrong
// hash, a file the server does not have.
type finalError struct{ error }

func (e finalError) Unwrap() error { return e.error }

func final(err error) error { return finalError{err} }

// retry runs f until it succeeds, fails finally, or has had len(retryWaits)+1 tries, and
// returns its last error.
func retry(ctx context.Context, log io.Writer, what string, f func() error) error {
	for i := 0; ; i++ {
		err := f()
		var fe finalError
		if err == nil || errors.As(err, &fe) || ctx.Err() != nil || i == len(retryWaits) {
			return err
		}
		fmt.Fprintf(log, "%s failed, trying again in %s: %v\n", what, retryWaits[i], err)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(retryWaits[i]):
		}
	}
}

// download gets url's body, up to limit bytes and one more, so that a caller can tell a
// body that is too large. A status the server would give again, such as 404, is final;
// a server error, or being asked to slow down, is tried again.
func download(ctx context.Context, log io.Writer, url string, limit int64) ([]byte, error) {
	var data []byte
	err := retry(ctx, log, "downloading "+url, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return final(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			err := fmt.Errorf("%s: %s", url, resp.Status)
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests {
				return final(err)
			}
			return err
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
		return err
	})
	return data, err
}
