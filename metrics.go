package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	probeDuration prometheus.Gauge
	probeSuccess  prometheus.Gauge
	sampleMetric  prometheus.Gauge
	sampleWidget  *prometheus.GaugeVec
)

func initCollectors() {
	probeDuration = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "probe_duration",
			Help: "How many seconds the probe took",
		},
	)

	probeSuccess = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "probe_success",
			Help: "Whether or not the probe succeeded",
		},
	)

	sampleMetric = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "sample_metric",
			Help: "An example gauge metric",
		},
	)

	sampleWidget = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sample_widget",
			Help: "An example gauge metric with a label",
		},
		[]string{"widget"},
	)
}
