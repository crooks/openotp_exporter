package main

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	prefix string = "openotp"
)

type prometheusMetrics struct {
	probeDuration  prometheus.Gauge
	probeSuccess   prometheus.Gauge
	usersMax       prometheus.Gauge
	usersActive    prometheus.Gauge
	serverEnabled  *prometheus.GaugeVec
	serverStatus   *prometheus.GaugeVec
	serverServices *prometheus.GaugeVec
}

func addPrefix(s string) string {
	return fmt.Sprintf("%s_%s", prefix, s)
}

func initCollectors() *prometheusMetrics {
	m := new(prometheusMetrics)
	m.probeDuration = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "probe_duration",
			Help: "How many seconds the probe took",
		},
	)

	m.probeSuccess = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "probe_success",
			Help: "Whether or not the probe succeeded",
		},
	)

	m.usersMax = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: addPrefix("users_max"),
			Help: "Maximum number of users the current OpenOTP license permits",
		},
	)

	m.usersActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: addPrefix("users_active"),
			Help: "Current number of license-consuming users",
		},
	)
	m.serverEnabled = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: addPrefix("server_enabled"),
			Help: "Is the OpenOTP server enabled",
		},
		[]string{"version"},
	)
	m.serverStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: addPrefix("server_status"),
			Help: "Status of the OpenOTP server",
		},
		[]string{"version"},
	)
	m.serverServices = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: addPrefix("server_services"),
			Help: "Status of the OpenOTP services",
		},
		[]string{"name"},
	)

	return m
}
