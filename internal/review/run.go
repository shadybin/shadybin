package review

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// parallel is how many units are reviewed at once.
const parallel = 4

// Run reviews the plan's units, from the cache where it has them, and decides the verdict.
func Run(ctx context.Context, in Inputs, plan *Plan, model Reviewer, cache *Cache, log io.Writer) (*Review, error) {
	r := &Review{Model: Model, Prompt: PromptVersion, Previous: in.PreviousTag, Modules: plan.Modules, Units: plan.Units}
	errs := make([]error, len(r.Units))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := range r.Units {
		u := &r.Units[i]
		if hit, err := cache.Lookup(ctx, u); err != nil {
			return nil, err
		} else if hit != nil {
			u.Result, u.ServedBy, u.Cached = hit.Result, hit.ServedBy, true
			fmt.Fprintf(log, "review: %s%s from the cache\n", u.Module, partName(*u))
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			mu.Lock()
			fmt.Fprintf(log, "review: %s%s, %d bytes\n", u.Module, partName(*u), len(u.input))
			mu.Unlock()
			res, servedBy, err := model.Review(ctx, u.input)
			if err != nil {
				errs[i] = fmt.Errorf("%s%s: %w", u.Module, partName(*u), err)
				return
			}
			u.Result, u.ServedBy = res, servedBy
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
