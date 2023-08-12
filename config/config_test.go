package config

import (
	"os"
	"testing"
)

func TestConfig(t *testing.T) {
	// First, create a config file in a temporary location
	testFile := getTestFile("testcfg")
	defer os.Remove(testFile.Name())
	writeCfg := new(Config)
	testLoglevel := "catastrophic"
	writeCfg.Logging.LevelStr = testLoglevel
	writeCfg.WriteConfig(testFile.Name())

	readCfg, err := ParseConfig(testFile.Name())
	if err != nil {
		t.Errorf("ParseConfig returned: %v", err)
	}
	if readCfg.Logging.LevelStr != testLoglevel {
		t.Errorf(
			"Unexpected readCfg.Logging.LevelStr. Expected=%s, Got=%s",
			testLoglevel, readCfg.Logging.LevelStr,
		)
	}
}

// getTestFile returns a temportary file instance
func getTestFile(filename string) (testFile *os.File) {
	testFile, err := os.CreateTemp("/tmp", filename)
	if err != nil {
		panic(err)
	}
	return
}
