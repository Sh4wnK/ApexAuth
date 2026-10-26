package service

import (
	"os"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

// TestMain starts one embedded PostgreSQL instance for the whole test
// binary (port 55432) and stops it afterwards. Each test seals its own data
// via TRUNCATE in newTestEnv.
func TestMain(m *testing.M) {
	code := run(m)
	os.Exit(code)
}

func run(m *testing.M) int {
	pg := startEmbeddedPG()
	if pg == nil {
		return 1
	}
	defer func() { _ = pg.Stop() }()
	return m.Run()
}

func startEmbeddedPG() *embeddedpostgres.EmbeddedPostgres {
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(testPGPort).
		Username("apexauth").
		Password("apexauth").
		Database("apexauth_test").
		RuntimePath(os.TempDir() + "/apexauth-test-pg/runtime").
		DataPath(os.TempDir() + "/apexauth-test-pg/data").
		BinariesPath(os.TempDir() + "/apexauth-test-pg/bin"))
	if err := pg.Start(); err != nil {
		// fall back to verbose panic so the test run reports it
		panic("embedded postgres start: " + err.Error())
	}
	return pg
}
