package review

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// inFlight bounds the input tokens of the units being reviewed at once. An organization's
// rate limit is in input tokens a minute, and one large unit takes about a minute, so this
// keeps a review under a 500k-a-minute limit with room to spare. A unit larger than this
// runs alone.
const inFlight = 400_000

// Run reviews the plan's units, from the shared cache or the local resume directory where
// they have them, and decides the verdict. Each unit answered is written to resume as
// soon as it is, so a run that fails partway, out of credit or rate-limited, can run
// again without paying for the units it already has. resume may be empty.
func Run(ctx context.Context, in Inputs, plan *Plan, model Reviewer, cache *Cache, resume string, log io.Writer) (*Review, error) {
	r := &Review{Model: Model, Prompt: PromptVersion, Previous: in.PreviousTag, Modules: plan.Modules, Units: plan.Units}
	errs := make([]error, len(r.Units))
	var wg sync.WaitGroup
	var mu sync.Mutex
	cond := sync.NewCond(&mu)
	used := 0
	for i := range r.Units {
		u := &r.Units[i]
		if hit, err := cache.Lookup(ctx, u); err != nil {
			return nil, err
		} else if hit != nil {
			u.Result, u.ServedBy, u.Cached = hit.Result, hit.ServedBy, true
			fmt.Fprintf(log, "review: %s%s from the cache\n", u.Module, partName(*u))
			continue
		}
		if done := resumed(resume, u); done != nil {
			u.Result, u.ServedBy = done.Result, done.ServedBy
			fmt.Fprintf(log, "review: %s%s from an earlier run\n", u.Module, partName(*u))
			continue
		}
		need := min(Tokens(u), inFlight)
		mu.Lock()
		for used > 0 && used+need > inFlight {
			cond.Wait()
		}
		used += need
		fmt.Fprintf(log, "review: %s%s, about %dk tokens\n", u.Module, partName(*u), Tokens(u)/1000)
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				mu.Lock()
				used -= need
				cond.Broadcast()
				mu.Unlock()
			}()
			res, servedBy, err := model.Review(ctx, u.input)
			if err != nil {
				errs[i] = fmt.Errorf("%s%s: %w", u.Module, partName(*u), err)
				return
			}
			u.Result, u.ServedBy = res, servedBy
			if err := save(resume, u); err != nil {
				errs[i] = err
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	r.Verdict, r.Reasons = Decide(r, in.Manifest, in.Previous)
	return r, nil
}

func resumePath(dir string, u *Unit) string {
	return filepath.Join(dir, strings.TrimPrefix(u.Digest, "sha256:")+".json")
}

// resumed is a unit an earlier run answered, with the same digest: the same model,
// prompt and input.
func resumed(dir string, u *Unit) *Unit {
	if dir == "" {
		return nil
	}
	data, err := os.ReadFile(resumePath(dir, u))
	if err != nil {
		return nil
	}
	var done Unit
	if json.Unmarshal(data, &done) != nil || done.Digest != u.Digest || done.Result == nil {
		return nil
	}
	return &done
}

func save(dir string, u *Unit) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(resumePath(dir, u), data, 0o644)
}
