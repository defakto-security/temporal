// Package dbauth gives Temporal's Postgres stores passwordless access to
// Amazon RDS through IAM database authentication (FRY-1422).
//
// An RDS IAM token is a presigned URL. Signing it is local CPU work, but the
// AWS credentials behind it (IRSA) refresh over the network. To keep both off
// the query path, a background loop signs a token ahead of time and keeps it
// in memory. A new database connection only reads that cached token.
package dbauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"

	"github.com/defakto-security/temporal/config"
)

// minRefreshInterval is the shortest accepted refresh interval. A var so
// tests can shorten it; never changed in production code.
var minRefreshInterval = config.MinRefreshInterval

const (
	// TokenLifetime is how long RDS accepts a token (a fixed 15 minutes).
	TokenLifetime = 15 * time.Minute
	// DefaultRefreshInterval is how often the background loop signs a new token.
	DefaultRefreshInterval = 10 * time.Minute
	// retryInterval is the wait after a failed refresh.
	retryInterval = 30 * time.Second
	// expiryMargin: a token this close to expiry is treated as expired, so a
	// connection never starts with a token that dies mid-handshake.
	expiryMargin = 30 * time.Second
	// refreshTimeout bounds one signing run, so a hung STS call cannot stall
	// the loop past the token's life.
	refreshTimeout = 20 * time.Second
	// refreshLead is how long before expiry the next refresh is due when the
	// token (or the AWS credentials behind it) expires sooner than the interval.
	refreshLead = 90 * time.Second
	// minWait floors the gap between refreshes.
	minWait = 5 * time.Second
)

// Options configures a TokenSource.
type Options struct {
	// Endpoint is the database "host:port" the token is for.
	Endpoint string
	// Region is the AWS region of the database.
	Region string
	// User is the database user mapped to the IAM role.
	User string
	// Credentials supplies AWS credentials (IRSA in the cluster).
	Credentials aws.CredentialsProvider
	// RefreshInterval is the gap between signing runs. It must be shorter
	// than TokenLifetime. Zero means DefaultRefreshInterval.
	RefreshInterval time.Duration
	// OnError is called when a refresh fails. May be nil.
	OnError func(error)
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// TokenSource holds the newest RDS IAM token and refreshes it in the background.
type TokenSource struct {
	opts Options

	mu      sync.RWMutex
	token   string
	expires time.Time

	cancel context.CancelFunc
	done   chan struct{}
}

// NewTokenSource signs the first token (failing fast if it cannot), then
// starts the refresh loop. Call Close to stop it.
func NewTokenSource(ctx context.Context, opts Options) (*TokenSource, error) {
	if opts.RefreshInterval == 0 {
		opts.RefreshInterval = DefaultRefreshInterval
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	t := &TokenSource{opts: opts, done: make(chan struct{})}
	if err := t.refresh(ctx); err != nil {
		return nil, fmt.Errorf("dbauth: first token for %s: %w", opts.Endpoint, err)
	}
	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	t.cancel = cancel
	go t.loop(loopCtx)
	return t, nil
}

func (o Options) validate() error {
	var errs []error
	if o.Endpoint == "" {
		errs = append(errs, errors.New("endpoint is required"))
	}
	if o.Region == "" {
		errs = append(errs, errors.New("region is required"))
	}
	if o.User == "" {
		errs = append(errs, errors.New("user is required"))
	}
	if o.Credentials == nil {
		errs = append(errs, errors.New("credentials are required"))
	}
	if o.RefreshInterval < minRefreshInterval || o.RefreshInterval >= TokenLifetime-expiryMargin {
		errs = append(errs, fmt.Errorf("refresh interval %s must be at least %s and shorter than %s",
			o.RefreshInterval, minRefreshInterval, TokenLifetime-expiryMargin))
	}
	return errors.Join(errs...)
}

// Token returns the cached token. It does no network work. It fails only when
// every refresh since the last good one has failed and the token has expired.
func (t *TokenSource) Token() (string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if !t.opts.Now().Before(t.expires.Add(-expiryMargin)) {
		return "", fmt.Errorf("dbauth: token for %s expired at %s and refresh is failing",
			t.opts.Endpoint, t.expires.Format(time.RFC3339))
	}
	return t.token, nil
}

// Close stops the refresh loop and waits for it to exit.
func (t *TokenSource) Close() {
	t.cancel()
	<-t.done
}

func (t *TokenSource) loop(ctx context.Context) {
	defer close(t.done)
	wait := t.nextWait()
	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err := t.refresh(ctx); err != nil {
			if t.opts.OnError != nil {
				t.opts.OnError(err)
			}
			// Keep the old token and retry soon; it stays valid until expiry.
			wait = retryInterval
			continue
		}
		wait = t.nextWait()
	}
}

// nextWait is the gap before the next refresh: the interval, or sooner when
// the current token expires before the interval ends.
func (t *TokenSource) nextWait() time.Duration {
	t.mu.RLock()
	expires := t.expires
	t.mu.RUnlock()
	wait := min(t.opts.RefreshInterval, expires.Sub(t.opts.Now())-refreshLead)
	return max(wait, min(minWait, t.opts.RefreshInterval))
}

func (t *TokenSource) refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	now := t.opts.Now()
	token, expires, err := buildToken(ctx, t.opts.Credentials, t.opts.Endpoint, t.opts.Region, t.opts.User, now)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.token, t.expires = token, expires
	t.mu.Unlock()
	return nil
}

// captureCreds remembers when the credentials it handed out expire.
type captureCreds struct {
	inner   aws.CredentialsProvider
	expires time.Time // zero when the credentials do not expire
}

func (c *captureCreds) Retrieve(ctx context.Context) (aws.Credentials, error) {
	cr, err := c.inner.Retrieve(ctx)
	if err == nil && cr.CanExpire {
		c.expires = cr.Expires
	}
	return cr, err
}

// buildToken signs an RDS IAM token with the AWS SDK's own rds/auth package
// and returns when it stops being usable: TokenLifetime from now, or sooner if
// the credentials that signed it expire first.
func buildToken(
	ctx context.Context,
	creds aws.CredentialsProvider,
	endpoint, region, user string,
	now time.Time,
) (string, time.Time, error) {
	cc := &captureCreds{inner: creds}
	token, err := auth.BuildAuthToken(ctx, endpoint, region, user, cc)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing RDS IAM token: %w", err)
	}
	expires := now.Add(TokenLifetime)
	if !cc.expires.IsZero() && cc.expires.Before(expires) {
		expires = cc.expires
	}
	return token, expires, nil
}
