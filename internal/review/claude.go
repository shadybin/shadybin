package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/shared/constant"
)

// Reviewer answers one unit. Claude is the real one; tests use their own.
type Reviewer interface {
	Review(ctx context.Context, input string) (result *Result, servedBy string, err error)
}

// Claude reviews with the Claude API. Its key comes from ANTHROPIC_API_KEY: in the certify
// workflow, the vendor's own, so the vendor pays for its reviews.
type Claude struct {
	Client anthropic.Client
}

// endpoint is the Claude API, fixed: the vendor runs the review, and a base URL from its
// environment could point it at a server that answers "pass" to everything.
const endpoint = "https://api.anthropic.com/"

// NewClaude returns a reviewer on the Claude API, with credentials from the environment.
func NewClaude() *Claude {
	return &Claude{Client: anthropic.NewClient(option.WithBaseURL(endpoint))}
}

// ErrRefused means the model declined to review, even after the fallback. It is never a
// verdict: the certify run fails, and can run again.
var ErrRefused = errors.New("the model declined to review this unit")

// Review sends one unit. Effort is high: the verdict decides what users install, with no
// person checking after. Refusals fall back server-side to another model, since reading
// code for malware can trip a classifier.
func (c *Claude) Review(ctx context.Context, input string) (*Result, string, error) {
	params := anthropic.BetaMessageNewParams{
		Model:     Model,
		MaxTokens: 64000,
		System: []anthropic.BetaTextBlockParam{{
			Text:         systemPrompt,
			CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
		}},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(input)),
		},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Effort: anthropic.BetaOutputConfigEffortHigh,
			Format: anthropic.BetaJSONOutputFormatParam{Schema: resultSchema},
		},
		Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
		Fallbacks: anthropic.BetaFallbacksParamUnion{OfDefault: constant.ValueOf[constant.Default]()},
	}
	stream := c.Client.Beta.Messages.NewStreaming(ctx, params)
	msg := anthropic.BetaMessage{}
	for stream.Next() {
		if err := msg.Accumulate(stream.Current()); err != nil {
			return nil, "", err
		}
	}
	if err := stream.Err(); err != nil {
		return nil, "", fmt.Errorf("claude: %w", err)
	}
	switch msg.StopReason {
	case anthropic.BetaStopReasonRefusal:
		return nil, string(msg.Model), fmt.Errorf("%w (%s)", ErrRefused, msg.StopDetails.Category)
	case anthropic.BetaStopReasonEndTurn:
	default:
		return nil, string(msg.Model), fmt.Errorf("claude stopped early: %s", msg.StopReason)
	}
	var text strings.Builder
	for _, block := range msg.Content {
		if t, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			text.WriteString(t.Text)
		}
	}
	r, err := parseResult(text.String())
	return r, string(msg.Model), err
}

// parseResult reads the model's JSON and checks what the schema cannot.
func parseResult(text string) (*Result, error) {
	var r Result
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("the review is not the expected JSON: %w", err)
	}
	if r.Verdict != "pass" && r.Verdict != "fail" {
		return nil, fmt.Errorf("the review's verdict is %q", r.Verdict)
	}
	for _, f := range r.Findings {
		switch f.Severity {
		case "info", "concern", "malicious":
		default:
			return nil, fmt.Errorf("a finding's severity is %q", f.Severity)
		}
	}
	return &r, nil
}
