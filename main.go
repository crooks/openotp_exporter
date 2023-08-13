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

// getLicenseDetails contains an incompleted subset of items returned from the API by "get_license_details".
type getLicenseDetails struct {
	CustomerID   string `json:"customer_id"`
	ErrorMessage string `json:"error_message"`
	InstanceID   string `json:"instance_id"`
	Products     struct {
		OpenOTP struct {
			MaximumUsers string `json:"maximum_users"`
		} `json:"OpenOTP"`
	} `json:"products"`
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

func boolToFloat(b bool) float64 {
	if !b {
		// False
		return 0
	}
	// True
	return 1
}

func apiBatchRequests(target string) (jsonrpc.RPCResponses, error) {
	var err error
	ctx := context.Background()
	rpcClient := newRPC(target)

	responses, _ := rpcClient.CallBatch(ctx, jsonrpc.RPCRequests{
		jsonrpc.NewRequest("Count_Activated_Users"),
		jsonrpc.NewRequest("Get_License_Details"),
		jsonrpc.NewRequest("Server_status", map[string]bool{
			"servers": true,
			"webapps": true,
			"websrvs": true,
		}),
	})
	if responses.HasError() {
		err = errors.New("RPC request returned errors")
	}
	return responses, err
}

func apiActiveUsers(response *jsonrpc.RPCResponse) (float64, error) {
	// Active Users is easy!  Only a simple integer is returned from the API.
	activeUsers, err := response.GetInt()
	if err != nil {
		newErr := fmt.Errorf("Unable to determine Activated Users: %v", err)
		return float64(activeUsers), newErr
	}
	return float64(activeUsers), err
}

func apiGetLicenseDetails(response *jsonrpc.RPCResponse) (float64, error) {
	// Maximum Users is burried in a messy nest.
	var lic *getLicenseDetails
	err := response.GetObject(&lic)
	if err != nil {
		log.Fatal(err)
	}
	maxUsers, err := strconv.ParseFloat(lic.Products.OpenOTP.MaximumUsers, 64)
	if err != nil {
		return maxUsers, err
	}
	return maxUsers, err
}

func apiServerStatus(response *jsonrpc.RPCResponse) (*serverStatusFields, error) {
	var status *serverStatusFields
	err := response.GetObject(&status)
	if err != nil {
		return status, err
	}
	fmt.Println(status.Enabled)
	fmt.Println(status.Version)
	return status, nil
}

func (m *prometheusMetrics) probeHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	target := params.Get("target")
	if target == "" {
		http.Error(w, "Target parameter missing or empty", http.StatusBadRequest)
		return
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(m.probeDuration)
	registry.MustRegister(m.probeSuccess)
	var success float64 = 1
	start := time.Now()
	responses, err := apiBatchRequests(target)
	if err != nil {
		success = 0
		log.Warnf("Probe of %s failed with %v", target, err)
	}
	if success == 1 {
		// Activated User Count
		au, err := apiActiveUsers(responses[0])
		if err != nil {
			log.Warn(err)
		} else {
			registry.MustRegister(m.usersActive)
			m.usersActive.Set(au)
		}
		// Licensed Users Count
		lu, err := apiGetLicenseDetails(responses[1])
		if err != nil {
			log.Warn(err)
		} else {
			registry.MustRegister(m.usersMax)
			m.usersMax.Set(lu)
		}
		// Server Status
		ss, err := apiServerStatus(responses[2])
		if err != nil {
			log.Warn(err)
		} else {
			registry.MustRegister(m.serverEnabled)
			registry.MustRegister(m.serverStatus)
			registry.MustRegister(m.serverServices)
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
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
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

	metrics := initCollectors()
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		metrics.probeHandler(w, r)
	})
	http.ListenAndServe("localhost:8080", nil)
}
