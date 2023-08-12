package main

import (
	stdlog "log"
	"net/http"
	"os"
	"time"

	"github.com/Masterminds/log-go"
	"github.com/crooks/jlog"
	loglevel "github.com/crooks/log-go-level"
	"github.com/crooks/prom_probe/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	cfg   *config.Config
	flags *config.Flags
)

func probe(widgetName string) error {
	sampleMetric.Set(float64(time.Now().Unix()))
	sampleWidget.WithLabelValues(widgetName).Set(1)
	return nil
}

func probeHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	target := params.Get("target")
	if target == "" {
		http.Error(w, "Target parameter missing or empty", http.StatusBadRequest)
		return
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(probeDuration)
	registry.MustRegister(probeSuccess)
	registry.MustRegister(sampleMetric)
	registry.MustRegister(sampleWidget)
	success := 1
	start := time.Now()
	err := probe("thingy")
	if err != nil {
		success = 0
		log.Warnf("Probe of %s failed with %v", target, err)
	}
	duration := time.Since(start).Seconds()
	probeSuccess.Set(float64(success))
	probeDuration.Set(duration)
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func main() {
	var err error
	flags = config.ParseFlags()
	cfg, err = config.ParseConfig(flags.Config)
	if err != nil {
		log.Fatalf("Cannot parse config: %v", err)
	}
	loglev, err := loglevel.ParseLevel(cfg.Logging.LevelStr)
	if err != nil {
		log.Fatalf("Unable to set log level: %v", err)
	}
	if cfg.Logging.Journal && !jlog.Enabled() {
		log.Warn("Cannot log to systemd journal")
	}
	if cfg.Logging.Journal && jlog.Enabled() {
		log.Current = jlog.NewJournal(loglev)
		log.Debugf("Logging to journal has been initialised at level: %s", cfg.Logging.LevelStr)
	} else {
		if cfg.Logging.Filename == "" {
			log.Fatal("Cannot log to file, no filename specified in config")
		}
		logWriter, err := os.OpenFile(cfg.Logging.Filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Unable to open logfile: %s", err)
		}
		defer logWriter.Close()
		stdlog.SetOutput(logWriter)
		log.Current = log.StdLogger{Level: loglev}
		log.Debugf("Logging to file %s has been initialised at level: %s", cfg.Logging.Filename, cfg.Logging.LevelStr)
	}
	initCollectors()
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r)
	})
	http.ListenAndServe("localhost:8080", nil)
}
