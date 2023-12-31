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
		Path     string `yaml:"path"`
	} `yaml:"api"`
	Logging struct {
		Filename string `yaml:"filename"`
		Journal  bool   `yaml:"journal"`
		LevelStr string `yaml:"level"`
	} `yaml:"logging"`
	Exporter struct {
		Hostname string `yaml:"hostname"`
		Port     int    `yaml:"port"`
	} `yaml:"exporter"`
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

	// Set some default values
	if config.API.Path == "" {
		config.API.Path = "manag/"
	}
	if config.Logging.LevelStr == "" {
		config.Logging.LevelStr = "info"
	}
	if config.Exporter.Port == 0 {
		// This is the default port assigned in the prometheus Wiki
		config.Exporter.Port = 9794
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
