package httpapi

import (
	"os"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

func TestMain(m *testing.M) {
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(55433).
		Username("apexauth").
		Password("apexauth").
		Database("apexauth_test").
		RuntimePath(os.TempDir() + "/apexauth-http-test-pg/runtime").
		DataPath(os.TempDir() + "/apexauth-http-test-pg/data").
		BinariesPath(os.TempDir() + "/apexauth-http-test-pg/bin"))
	if err := pg.Start(); err != nil {
		panic("embedded postgres start: " + err.Error())
	}
	code := m.Run()
	_ = pg.Stop()
	os.Exit(code)
}
