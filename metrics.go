package main

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	prefix string = "openotp"
)

type prometheusMetrics struct {
	probeDuration    prometheus.Gauge
	probeSuccess     prometheus.Gauge
	licenseMaxUsers  *prometheus.GaugeVec
	licenseValidFrom *prometheus.GaugeVec
	licenseValidTo   *prometheus.GaugeVec
	usersActive      prometheus.Gauge
	serverEnabled    *prometheus.GaugeVec
	serverStatus     *prometheus.GaugeVec
	serverServices   *prometheus.GaugeVec
}

func addPrefix(s string) string {
	return fmt.Sprintf("%s_%s", prefix, s)
}

func initCollectors(reg *prometheus.Registry) *prometheusMetrics {
	m := new(prometheusMetrics)
	m.probeDuration = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "probe_duration",
			Help: "How many seconds the probe took",
		},
	)
	reg.MustRegister(m.probeDuration)

	m.probeSuccess = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "probe_success",
			Help: "Whether or not the probe succeeded",
		},
	)
	reg.MustRegister(m.probeSuccess)

	m.licenseMaxUsers = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: addPrefix("license_users_max"),
			Help: "Maximum number of users the current OpenOTP license permits",
		},
		[]string{"customer", "license"},
	)
	reg.MustRegister(m.licenseMaxUsers)

	m.licenseValidFrom = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: addPrefix("license_valid_from"),
			Help: "Epoch timestamp of license start date",
		},
		[]string{"customer", "license"},
	)
	reg.MustRegister(m.licenseValidFrom)

	m.licenseValidTo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: addPrefix("license_valid_to"),
			Help: "Epoch timestamp of license end date",
		},
		[]string{"customer", "license"},
	)
	reg.MustRegister(m.licenseValidTo)

	m.usersActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: addPrefix("users_active"),
			Help: "Current number of license-consuming users",
		},
	)
	reg.MustRegister(m.usersActive)

	m.serverEnabled = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: addPrefix("server_enabled"),
			Help: "Is the OpenOTP server enabled",
		},
		[]string{"version"},
	)
	reg.MustRegister(m.serverEnabled)

	m.serverStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: addPrefix("server_status"),
			Help: "Status of the OpenOTP server",
		},
		[]string{"version"},
	)
	reg.MustRegister(m.serverStatus)

	m.serverServices = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: addPrefix("server_services"),
			Help: "Status of the OpenOTP services",
		},
		[]string{"name"},
	)
	reg.MustRegister(m.serverServices)

	return m
}
