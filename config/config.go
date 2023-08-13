package config

import (
	"flag"
	"os"
	"os/user"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// Flags are command line arguments
type Flags struct {
	Config string
}

type Config struct {
	API struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		CertFile string `yaml:"certfile"`
	} `yaml:"api"`
	Logging struct {
		Filename string `yaml:"filename"`
		Journal  bool   `yaml:"journal"`
		LevelStr string `yaml:"level"`
	} `yaml:"logging"`
}

// ParseConfig imports a yaml formatted config file into a Config struct
func ParseConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	d := yaml.NewDecoder(file)
	if err := d.Decode(&config); err != nil {
		return nil, err
	}
	return config, nil
}

// parseFlags processes arguments passed on the command line in the format
// standard format: --foo=bar
func ParseFlags() *Flags {
	f := new(Flags)
	flag.StringVar(&f.Config, "config", "config.yml", "Path to configuration file")
	flag.Parse()
	return f
}

// WriteConfig will create a YAML formatted config file from a Config struct
func (c *Config) WriteConfig(filename string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

// expandTilde expands filenames and paths that use the tilde convention to imply relative to homedir.
func expandTilde(inPath string) (outPath string) {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	if inPath == "~" {
		outPath = u.HomeDir
	} else if strings.HasPrefix(inPath, "~/") {
		outPath = path.Join(u.HomeDir, inPath[2:])
	} else {
		outPath = inPath
	}
	return
}
