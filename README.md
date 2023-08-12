# prom_probe

## Description
While this code is functional, it's real purpose is to provide a framework for creating new Prometheus Multi-Target Exporters.
The metrics themselves are defined in `metrics.go`.  The function called `probe` that resides in `main.go` should be replaced with whatever API or endpoint is being queried.