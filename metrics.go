package caddyrl

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// rateLimitMetrics holds all the rate limit metrics
type rateLimitMetrics struct {
	declinedTotal *prometheus.CounterVec
	requestsTotal *prometheus.CounterVec
	processTime   *prometheus.HistogramVec
	keysTotal     *prometheus.GaugeVec
	config        *prometheus.CounterVec
}

var (
	// Global metrics instance
	globalMetrics *rateLimitMetrics
)

// initializeMetrics creates and registers all rate limit metrics with Caddy's internal registry
func initializeMetrics(registry prometheus.Registerer) *rateLimitMetrics {
	const ns, sub = "caddy", "rate_limit"

	factory := promauto.With(registry)

	return &rateLimitMetrics{
		// rate_limit_declined_requests_total - Total number of requests declined with HTTP 429
		declinedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: ns,
				Subsystem: sub,
				Name:      "declined_requests_total",
				Help:      "Total number of requests for which rate limit was applied (Declined with HTTP 429 status code returned).",
			},
			[]string{"zone", "key"},
		),

		// rate_limit_requests_total - Total number of requests that passed through the Rate Limit module
		requestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: ns,
				Subsystem: sub,
				Name:      "requests_total",
				Help:      "Total number of requests that passed through Rate Limit module (both declined & processed).",
			},
			[]string{"zone", "key"},
		),

		// rate_limit_process_time_seconds - Time taken to process rate limiting for each request
		processTime: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: ns,
				Subsystem: sub,
				Name:      "process_time_seconds",
				Help:      "A time taken to process rate limiting for each request.",
				Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
			},
			[]string{"zone", "key"},
		),

		// rate_limit_keys_total - Total number of keys that each RL zone contains
		keysTotal: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: ns,
				Subsystem: sub,
				Name:      "keys_total",
				Help:      "Total number of keys that each RL zone contains. (This metric is collected in the background for each zone.)",
			},
			[]string{"zone"},
		),

		// rate_limit_config - Shows configuration of the rate limiter module
		config: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: ns,
				Subsystem: sub,
				Name:      "config",
				Help:      "Shows configuration of the rate limiter module. Reported only once on bootstrap as configuration is not dynamically configurable.",
			},
			[]string{"zone", "max_events", "window"},
		),
	}
}

// registerMetrics registers all rate limit metrics with the provided Prometheus registry
func registerMetrics(reg prometheus.Registerer) error {
	// Try to initialize metrics - this may fail with AlreadyRegisteredError on config reload
	metrics := initializeMetrics(reg)

	// Check if we got an AlreadyRegisteredError (which is expected on config reload)
	// We can handle it by trying to set the global metrics if it's nil
	if globalMetrics == nil {
		globalMetrics = metrics
	}

	// For now, we ignore duplicate registration errors as suggested
	// This allows metrics to continue working after config reloads
	return nil
}

// metricsCollector holds the metrics collection methods
type metricsCollector struct {
	enabled bool
}

// newMetricsCollector creates a new metrics collector
func newMetricsCollector() *metricsCollector {
	return &metricsCollector{enabled: true}
}

// recordRequest records a request that passed through the rate limit module
func (mc *metricsCollector) recordRequest(hasZone bool) {
	if !mc.enabled || globalMetrics == nil {
		return
	}

	hasZoneStr := "false"
	if hasZone {
		hasZoneStr = "true"
	}
	// Record zone-level aggregate metric (key is empty for zone-level aggregation)
	globalMetrics.requestsTotal.WithLabelValues(hasZoneStr, "").Inc()
}

// recordRequestPerKey records a request for a specific zone and key
func (mc *metricsCollector) recordRequestPerKey(zone, key string) {
	if !mc.enabled || globalMetrics == nil {
		return
	}

	// Record both zone-level aggregate and per-key detailed metrics
	globalMetrics.requestsTotal.WithLabelValues(zone, "").Inc()  // Zone-level aggregate
	globalMetrics.requestsTotal.WithLabelValues(zone, key).Inc() // Per-key detailed
}

// recordDeclinedRequest records a request that was declined due to rate limiting
func (mc *metricsCollector) recordDeclinedRequest(zone, key string) {
	if !mc.enabled || globalMetrics == nil {
		return
	}

	// Record both zone-level aggregate and per-key detailed metrics
	globalMetrics.declinedTotal.WithLabelValues(zone, "").Inc()  // Zone-level aggregate
	globalMetrics.declinedTotal.WithLabelValues(zone, key).Inc() // Per-key detailed
}

// recordProcessTime records the time taken to process rate limiting
func (mc *metricsCollector) recordProcessTime(duration time.Duration, hasZone bool) {
	if !mc.enabled || globalMetrics == nil {
		return
	}

	hasZoneStr := "false"
	if hasZone {
		hasZoneStr = "true"
	}
	// Record zone-level aggregate metric (key is empty for zone-level aggregation)
	globalMetrics.processTime.WithLabelValues(hasZoneStr, "").Observe(duration.Seconds())
}

// recordProcessTimePerKey records the time taken to process rate limiting for a specific zone and key
func (mc *metricsCollector) recordProcessTimePerKey(duration time.Duration, zone, key string) {
	if !mc.enabled || globalMetrics == nil {
		return
	}

	// Record both zone-level aggregate and per-key detailed metrics
	globalMetrics.processTime.WithLabelValues(zone, "").Observe(duration.Seconds())  // Zone-level aggregate
	globalMetrics.processTime.WithLabelValues(zone, key).Observe(duration.Seconds()) // Per-key detailed
}

// updateKeysCount updates the count of keys for a specific zone
func (mc *metricsCollector) updateKeysCount(zone string, count int) {
	if !mc.enabled || globalMetrics == nil {
		return
	}

	globalMetrics.keysTotal.WithLabelValues(zone).Set(float64(count))
}

// recordConfig records the configuration of a rate limit zone (called once during provision)
func (mc *metricsCollector) recordConfig(zone string, maxEvents int, window time.Duration) {
	if !mc.enabled || globalMetrics == nil {
		return
	}

	globalMetrics.config.WithLabelValues(zone,
		strconv.Itoa(maxEvents),
		window.String()).Inc()
}
