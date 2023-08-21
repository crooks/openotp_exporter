package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Masterminds/log-go"
	"github.com/crooks/jlog"
	loglevel "github.com/crooks/log-go-level"
	"github.com/crooks/openotp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ybbus/jsonrpc/v3"
)

var (
	cfg   *config.Config
	flags *config.Flags
)

// licenseDetailsFields contains an incompleted subset of items returned from the API by "get_license_details".
type licenseDetailsFields struct {
	CustomerID   string `json:"customer_id"`
	ErrorMessage string `json:"error_message"`
	InstanceID   string `json:"instance_id"`
	Products     struct {
		OpenOTP struct {
			MaximumUsers string `json:"maximum_users"`
		} `json:"OpenOTP"`
	} `json:"products"`
	ValidFrom string `json:"valid_from"`
	ValidTo   string `json:"valid_to"`
}

type serverStatusFields struct {
	Enabled bool `json:"enabled"`
	Servers struct {
		Ldap    bool `json:"ldap"`
		Mail    bool `json:"mail"`
		Pki     bool `json:"pki"`
		Proxy   bool `json:"proxy"`
		Session bool `json:"session"`
		Sql     bool `json:"sql"`
	} `json:"servers"`
	Status  bool   `json:"status"`
	Version string `json:"version"`
}

// boolToFloat converts booleans to 1 or 0 for ingestion by Prometheus. 1=Yes, 0=No.
func boolToFloat(b bool) float64 {
	if !b {
		// False
		return 0
	}
	// True
	return 1
}

// strToEpoch converts OpenOTPs date/time string format to Unix Epoch.
func strToEpoch(s string) float64 {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		log.Warnf("Cannot convert %s to date/time")
		return 0
	}
	return float64(t.Unix())
}

// apiBatchRequests performs a sequence of RPC requests to OpenOTP.  This is preferred to lots of individual requests
// as OpenOTP uses (horrible) TLS renegotiation.
func apiBatchRequests(target string) (jsonrpc.RPCResponses, error) {
	var err error
	ctx := context.Background()
	rpcClient := newRPC(target)

	responses, err := rpcClient.CallBatch(ctx, jsonrpc.RPCRequests{
		jsonrpc.NewRequest("Count_Activated_Users"),
		jsonrpc.NewRequest("Get_License_Details"),
		jsonrpc.NewRequest("Server_status", map[string]bool{
			"servers": true,
			"webapps": true,
			"websrvs": true,
		}),
	})
	if err != nil {
		return responses, err
	}
	if responses.HasError() {
		err = errors.New("RPC request returned errors")
	}
	if len(responses) != 3 {
		err = fmt.Errorf("unexpected batch response from %s.  expected=3, got=%d ", target, len(responses))
	}
	return responses, err
}

// activeUsers extracts the number of actived users from OpenOTP
func apiActiveUsers(response *jsonrpc.RPCResponse) (float64, error) {
	// Active Users is easy!  Only a simple integer is returned from the API.
	activeUsers, err := response.GetInt()
	if err != nil {
		newErr := fmt.Errorf("unable to determine activated users: %v", err)
		return float64(activeUsers), newErr
	}
	return float64(activeUsers), err
}

func apiGetLicenseDetails(response *jsonrpc.RPCResponse) (*licenseDetailsFields, error) {
	var lic *licenseDetailsFields
	err := response.GetObject(&lic)
	if err != nil {
		return lic, err
	}
	return lic, err
}

func apiServerStatus(response *jsonrpc.RPCResponse) (*serverStatusFields, error) {
	var status *serverStatusFields
	err := response.GetObject(&status)
	if err != nil {
		return status, err
	}
	return status, nil
}

func (m *prometheusMetrics) probeHandler(w http.ResponseWriter, r *http.Request, reg *prometheus.Registry) {
	params := r.URL.Query()
	target := params.Get("target")
	if target == "" {
		http.Error(w, "Target parameter missing or empty", http.StatusBadRequest)
		return
	}
	var success float64 = 1
	start := time.Now()
	responses, err := apiBatchRequests(target)
	if err != nil {
		success = 0
		log.Warnf("Probe of %s failed with %v", target, err)
	}
	// If the apiBatchResponse was successful, there will be an array of responses to process.
	if success == 1 {
		// Activated User Count
		au, err := apiActiveUsers(responses[0])
		if err != nil {
			log.Warn(err)
		} else {
			m.usersActive.Set(au)
		}
		// Licensed Users Count
		license, err := apiGetLicenseDetails(responses[1])
		if err != nil {
			log.Warn(err)
		} else {
			mu, err := strconv.ParseFloat(license.Products.OpenOTP.MaximumUsers, 64)
			if err != nil {
				log.Warn(err)
			} else {
				m.licenseMaxUsers.WithLabelValues(license.CustomerID, license.InstanceID).Set(mu)
			}
			m.licenseValidFrom.WithLabelValues(license.CustomerID, license.InstanceID).Set(strToEpoch(license.ValidFrom))
			m.licenseValidTo.WithLabelValues(license.CustomerID, license.InstanceID).Set(strToEpoch(license.ValidTo))
		}
		// Server Status
		ss, err := apiServerStatus(responses[2])
		if err != nil {
			log.Warn(err)
		} else {
			m.serverEnabled.WithLabelValues(ss.Version).Set(boolToFloat(ss.Enabled))
			m.serverStatus.WithLabelValues(ss.Version).Set(boolToFloat(ss.Status))
			m.serverServices.WithLabelValues("ldap").Set(boolToFloat(ss.Servers.Ldap))
			m.serverServices.WithLabelValues("mail").Set(boolToFloat(ss.Servers.Mail))
			m.serverServices.WithLabelValues("pki").Set(boolToFloat(ss.Servers.Pki))
			m.serverServices.WithLabelValues("proxy").Set(boolToFloat(ss.Servers.Proxy))
			m.serverServices.WithLabelValues("session").Set(boolToFloat(ss.Servers.Session))
			m.serverServices.WithLabelValues("sql").Set(boolToFloat(ss.Servers.Sql))
		}
	}
	duration := time.Since(start).Seconds()
	m.probeSuccess.Set(success)
	m.probeDuration.Set(duration)
	h := promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})
	h.ServeHTTP(w, r)
}

func newRPC(url string) jsonrpc.RPCClient {
	auth := fmt.Sprintf("%s:%s", cfg.API.Username, cfg.API.Password)
	authb64 := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
	}
	rpcClient := jsonrpc.NewClientWithOpts(url,
		&jsonrpc.RPCClientOpts{
			HTTPClient: &http.Client{
				Transport: tr,
			},
			CustomHeaders: map[string]string{
				"Authorization": authb64,
			},
		},
	)
	return rpcClient
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
	if cfg.Logging.Journal && jlog.Enabled() {
		log.Current = jlog.NewJournal(loglev)
		log.Infof("Logging to journal has been initialised at level: %s", cfg.Logging.LevelStr)
	} else {
		// Journal is not available
		if cfg.Logging.Journal {
			log.Warn("Configured for journal logging but journal is not available.  Logging to file instead.")
		}
		var logWriter *os.File
		if cfg.Logging.Filename == "" {
			// Create a temporary file for logging
			logWriter, err = os.CreateTemp("", "openotp_exporter.log")
			if err != nil {
				log.Fatalf("Cannot log to temp file: %v", err)
			}
			fmt.Printf("Logging to: %s", logWriter.Name())
		} else {
			// Log to the configured file
			logWriter, err = os.OpenFile(cfg.Logging.Filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				log.Fatalf("Unable to open logfile: %s", err)
			}
		}
		defer logWriter.Close()
		stdlog.SetOutput(logWriter)
		log.Current = log.StdLogger{Level: loglev}
		log.Debugf("Logging to file %s has been initialised at level: %s", logWriter.Name(), cfg.Logging.LevelStr)
	}

	registry := prometheus.NewRegistry()
	metrics := initCollectors(registry)
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		metrics.probeHandler(w, r, registry)
	})
	hostport := fmt.Sprintf("%s:%d", cfg.Exporter.Hostname, cfg.Exporter.Port)
	if cfg.Exporter.Hostname == "" {
		log.Infof("Listening on all interfaces on port %d", cfg.Exporter.Port)
	} else {
		log.Infof("Listening on %s", hostport)
	}
	http.ListenAndServe(hostport, nil)
}
