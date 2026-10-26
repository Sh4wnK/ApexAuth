// Command bench is a load tester for the ApexAuth HTTP API. It performs
// password logins and token validations against a running server with the
// Redis cache on or off and reports p50/p95/p99 latencies.
//
// Usage:
//
//	bench -users 500 -concurrency 40 -duration 20s -cache on
//	bench -users 500 -concurrency 40 -duration 20s -cache off
//
// The numbers it prints are measured on the machine it runs on (see README
// "Performance" for the recorded results and commands).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type loginResp struct {
	AccessToken string `json:"access_token"`
}

type config struct {
	baseURL     string
	users       int
	concurrency int
	duration    time.Duration
	cache       string
	loginFrac   float64 // fraction of requests that are logins vs validations
}

func main() {
	var cfg config
	flag.StringVar(&cfg.baseURL, "base", "http://localhost:8080", "ApexAuth base URL")
	flag.IntVar(&cfg.users, "users", 500, "number of distinct test users to log in as")
	flag.IntVar(&cfg.concurrency, "concurrency", 40, "number of concurrent workers")
	flag.DurationVar(&cfg.duration, "duration", 20*time.Second, "measurement window")
	flag.StringVar(&cfg.cache, "cache", "on", "on or off (compare the two)")
	flag.Float64Var(&cfg.loginFrac, "login-frac", 0.5, "fraction of requests that are logins")
	flag.Parse()

	if cfg.cache != "on" && cfg.cache != "off" {
		fmt.Fprintln(os.Stderr, "-cache must be 'on' or 'off'")
		os.Exit(2)
	}
	lat, err := run(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
	report(cfg, lat)
}

func run(ctx context.Context, cfg config) ([]time.Duration, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	var (
		latMu    sync.Mutex
		lats     []time.Duration
		okCount  atomic.Int64
		errCount atomic.Int64
	)
	emails := make([]string, cfg.users)
	for i := range emails {
		emails[i] = fmt.Sprintf("user%04d@apexauth.dev", i)
	}
	tokens := make([]string, cfg.users)

	// Pre-login to obtain access tokens for the validation leg.
	for i := 0; i < cfg.users; i++ {
		tok, err := login(client, cfg.baseURL, emails[i])
		if err != nil {
			return nil, fmt.Errorf("pre-login user %d: %w", i, err)
		}
		tokens[i] = tok
	}

	deadline := time.Now().Add(cfg.duration)
	start := time.Now()
	var wg sync.WaitGroup
	work := make(chan int)
	for w := 0; w < cfg.concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rnd := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), uint64(w)))
			for i := range work {
				if time.Now().After(deadline) {
					break
				}
				var (
					err error
					d   time.Duration
				)
				if rnd.Float64() < cfg.loginFrac {
					d, err = loginTimed(client, cfg.baseURL, emails[i%len(emails)])
				} else {
					d, err = validateTimed(client, cfg.baseURL, tokens[i%len(tokens)])
				}
				if err != nil {
					errCount.Add(1)
					continue
				}
				okCount.Add(1)
				latMu.Lock()
				lats = append(lats, d)
				latMu.Unlock()
			}
		}()
	}
	i := 0
	for time.Now().Before(deadline) {
		select {
		case work <- i:
			i++
		case <-ctx.Done():
			break
		}
	}
	close(work)
	wg.Wait()
	latMu.Lock()
	defer latMu.Unlock()
	sort.Slice(lats, func(a, b int) bool { return lats[a] < lats[b] })
	_ = okCount.Load()
	_ = errCount.Load()
	_ = start
	return lats, nil
}

func login(client *http.Client, base, email string) (string, error) {
	body, _ := json.Marshal(map[string]string{"email": email, "password": "password123"})
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login %s: status %d", email, resp.StatusCode)
	}
	var lr loginResp
	if err := json.Unmarshal(data, &lr); err != nil {
		return "", err
	}
	return lr.AccessToken, nil
}

func loginTimed(client *http.Client, base, email string) (time.Duration, error) {
	body, _ := json.Marshal(map[string]string{"email": email, "password": "password123"})
	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := client.Do(req)
	d := time.Since(start)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("login %s: status %d", email, resp.StatusCode)
	}
	return d, nil
}

func validateTimed(client *http.Client, base, token string) (time.Duration, error) {
	req, _ := http.NewRequest(http.MethodGet, base+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	start := time.Now()
	resp, err := client.Do(req)
	d := time.Since(start)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("validate: status %d", resp.StatusCode)
	}
	return d, nil
}

func report(cfg config, lats []time.Duration) {
	if len(lats) == 0 {
		fmt.Println("no successful requests recorded")
		return
	}
	p := func(q float64) time.Duration { return lats[int(float64(len(lats)-1)*q)] }
	fmt.Printf("cache=%s requests=%d p50=%s p95=%s p99=%s\n",
		cfg.cache, len(lats), p(0.50), p(0.95), p(0.99))
}
