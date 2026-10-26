// Throwaway driver: boots the real ApexAuth HTTP server against
// embedded-postgres + miniredis, seeds N users, and exercises the same HTTP
// workload as cmd/bench (POST /api/v1/login, GET /oauth2/userinfo) with the
// cache on and off, reporting p50/p95/p99.
package benchtest

import (
	"bytes"
	"context"
	"crypto/rand"

	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sh4wnK/ApexAuth/internal/cache"
	"github.com/Sh4wnK/ApexAuth/internal/httpapi"

	"github.com/Sh4wnK/ApexAuth/internal/mailer"
	"github.com/Sh4wnK/ApexAuth/internal/migrate"
	"github.com/Sh4wnK/ApexAuth/internal/passwd"
	"github.com/Sh4wnK/ApexAuth/internal/service"
	"github.com/Sh4wnK/ApexAuth/internal/store"
	"github.com/Sh4wnK/ApexAuth/internal/tokens"
	"github.com/alicebob/miniredis/v2"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

func TestDriverRun(t *testing.T) {
	if os.Getenv("APEXAUTH_BENCH") == "" {
		t.Skip("set APEXAUTH_BENCH=1 to run the in-process load benchmark (takes ~1 min)")
	}
	ctx := context.Background()

	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(55477).Username("apexauth").Password("apexauth").Database("apexauth").
		RuntimePath(os.TempDir() + "/ab-bench-pg/rt").DataPath(os.TempDir() + "/ab-bench-pg/data").BinariesPath(os.TempDir() + "/ab-bench-pg/bin"))
	if err := pg.Start(); err != nil {
		t.Fatal(err)
	}
	defer pg.Stop()
	dsn := "postgres://apexauth:apexauth@localhost:55477/apexauth?sslmode=disable"
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(ctx, conn); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)

	mr, _ := miniredis.Run()
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	// --- build server (cache on) ---
	bench := func(cacheOn bool) {
		if cacheOn {
			rdb.FlushDB(ctx)
		}
		st, _ := store.New(ctx, dsn)
		defer st.Close()
		ca, _ := cache.New("", "", 0, cacheOn)
		_ = ca
		var ca2 *cache.Cache
		if cacheOn {
			ca2 = cache.NewFromClient(rdb)
		} else {
			ca2, _ = cache.New("", "", 0, false)
		}
		signer, _ := tokens.NewSigner(tokens.Options{Alg: "ed25519"})
		defer signer.Close()
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		tk := service.NewTokens(st, ca2, signer, "http://localhost:8080", 15*time.Minute, 720*time.Hour, 720*time.Hour, log)
		oauth := service.NewOAuth(st, tk, 5*time.Minute, "http://localhost:8080", log)
		_ = oauth

		// seed 500 users
		_, _ = st.EnsureRole(ctx, "member", "")
		for i := 0; i < 500; i++ {
			email := fmt.Sprintf("bench%04d@apexauth.dev", i)
			if _, err := st.GetUserByEmail(ctx, email); err != nil {
				u, _ := st.CreateUser(ctx, email, fmt.Sprintf("Bench %d", i), true)
				phc, _ := passwd.Hash("password123")
				_ = st.SetPassword(ctx, u.ID, phc)
				_ = st.AssignRole(ctx, u.ID, "member")
			}
		}

		secret := make([]byte, 32)
		rand.Read(secret)
		pw := service.NewPasswordless(st, &nopMail{}, "noreply@t", time.Minute, log)
		srv, srvErr := httpapi.New(httpapi.Options{
			Store: st, Cache: ca2, Tokens: tk, OAuth: oauth, Passwordless: pw, Signer: signer,
			Issuer: "http://localhost:8080", BaseURL: "http://localhost:8080",
			HMACSecret: secret, RateLimitMax: 100000, RateWindow: time.Minute, AttemptsMax: 100, Log: log,
		})
		if srvErr != nil {
			t.Fatal(srvErr)
		}
		ts := httptest.NewServer(srv.Handler())
		defer ts.Close()

		// pre-login to get tokens
		tokens := make([]string, 500)
		for i := 0; i < 500; i++ {
			email := fmt.Sprintf("bench%04d@apexauth.dev", i)
			tok, err := login(ts.URL, email)
			if err != nil {
				t.Fatal(err)
			}
			tokens[i] = tok
		}

		var lats []time.Duration
		var mu sync.Mutex
		var okC, errC atomic.Int64
		stop := time.Now().Add(15 * time.Second)
		var wg sync.WaitGroup
		for w := 0; w < 40; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				i := w
				for time.Now().Before(stop) {
					sel := i % 2
					var d time.Duration
					var err error
					if sel == 0 {
						d, err = loginTimed(ts.URL, fmt.Sprintf("bench%04d@apexauth.dev", i%500))
					} else {
						d, err = validateTimed(ts.URL, tokens[i%500])
					}
					if err != nil {
						errC.Add(1)
					} else {
						okC.Add(1)
						mu.Lock()
						lats = append(lats, d)
						mu.Unlock()
					}
					i++
				}
			}(w)
		}
		wg.Wait()
		sort.Slice(lats, func(a, b int) bool { return lats[a] < lats[b] })
		p := func(q float64) time.Duration { return lats[int(float64(len(lats)-1)*q)] }
		mode := "off"
		if cacheOn {
			mode = "on"
		}
		fmt.Printf("cache=%s requests=%d ok=%d p50=%s p95=%s p99=%s\n", mode, len(lats), okC.Load(), p(0.50), p(0.95), p(0.99))
	}
	bench(true)
	bench(false)
}

func login(base, email string) (string, error) {
	b, _ := json.Marshal(map[string]string{"email": email, "password": "password123"})
	resp, err := http.Post(base+"/api/v1/login", "application/json", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login %s: %d", email, resp.StatusCode)
	}
	var lr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &lr); err != nil {
		return "", err
	}
	return lr.AccessToken, nil
}

func loginTimed(base, email string) (time.Duration, error) {
	b, _ := json.Marshal(map[string]string{"email": email, "password": "password123"})
	req, _ := http.NewRequest("POST", base+"/api/v1/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	d := time.Since(start)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("login %d", resp.StatusCode)
	}
	return d, nil
}

func validateTimed(base, token string) (time.Duration, error) {
	req, _ := http.NewRequest("GET", base+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	d := time.Since(start)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("validate %d", resp.StatusCode)
	}
	return d, nil
}

type nopMail struct{}

func (n *nopMail) Send(_ context.Context, msg mailer.Message) error { return nil }
