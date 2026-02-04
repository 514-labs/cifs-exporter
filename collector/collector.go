package collector

import (
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/shibumi/cifs-exporter/cifs"
)

type CIFSCollector struct {
	metrics map[string]*prometheus.Desc
	mutex   sync.Mutex
	up      *prometheus.Desc
}

// NewCIFSCollector creates a CIFSCollector
func NewCIFSCollector() *CIFSCollector {
	return &CIFSCollector{
		metrics: map[string]*prometheus.Desc{
			"cifs_total_cifs_sessions":        prometheus.NewDesc("cifs_total_cifs_sessions", "Total CIFS sessions", nil, nil),
			"cifs_total_unique_mount_targets": prometheus.NewDesc("cifs_total_unique_mount_targets", "Total unique mount targets", nil, nil),
			"cifs_total_requests":             prometheus.NewDesc("cifs_total_requests", "Total requests", nil, nil),
			"cifs_total_buffer":               prometheus.NewDesc("cifs_total_buffer", "Total buffer", nil, nil),
			"cifs_total_small_requests":       prometheus.NewDesc("cifs_total_small_requests", "Total small requests", nil, nil),
			"cifs_total_small_buffer":         prometheus.NewDesc("cifs_total_small_buffer", "Total small buffer", nil, nil),
			"cifs_total_op":                   prometheus.NewDesc("cifs_total_op", "Total op", nil, nil),
			"cifs_total_session":              prometheus.NewDesc("cifs_total_session", "Total session", nil, nil),
			"cifs_total_share_reconnects":     prometheus.NewDesc("cifs_total_share_reconnects", "Total share reconnects", nil, nil),
			"cifs_total_max_op":               prometheus.NewDesc("cifs_total_max_op", "Total max op", nil, nil),
			"cifs_total_at_once":              prometheus.NewDesc("cifs_total_at_once", "Total operations at once", nil, nil),
			"cifs_max_requests_in_flight":     prometheus.NewDesc("cifs_max_requests_in_flight", "Max concurrent requests in flight (concurrency pressure indicator)", nil, nil),
		},
		up: prometheus.NewDesc("cifs_up", "Boolean gauge of 1 if cifs shares are available, or 0 if not", nil, nil),
	}
}

// Describe outputs metrics descriptions.
func (c *CIFSCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range c.metrics {
		ch <- m
	}
}

func (c *CIFSCollector) Collect(ch chan<- prometheus.Metric) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	stats, err := cifs.NewClientStats()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, float64(0))
		return
	}
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, float64(1))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_cifs_sessions"], prometheus.GaugeValue, float64(stats.Header.CIFSSession))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_unique_mount_targets"], prometheus.GaugeValue, float64(stats.Header.Targets))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_requests"], prometheus.GaugeValue, float64(stats.Header.SMBReq))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_buffer"], prometheus.GaugeValue, float64(stats.Header.SMBBuf))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_small_requests"], prometheus.GaugeValue, float64(stats.Header.SMBSmallReq))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_small_buffer"], prometheus.GaugeValue, float64(stats.Header.SMBSmallBuf))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_op"], prometheus.GaugeValue, float64(stats.Header.Op))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_session"], prometheus.GaugeValue, float64(stats.Header.Session))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_share_reconnects"], prometheus.GaugeValue, float64(stats.Header.ShareReconnects))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_max_op"], prometheus.GaugeValue, float64(stats.Header.MaxOp))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_total_at_once"], prometheus.GaugeValue, float64(stats.Header.AtOnce))
	ch <- prometheus.MustNewConstMetric(c.metrics["cifs_max_requests_in_flight"], prometheus.GaugeValue, float64(stats.Header.MaxRequestsInFlight))

	// Process blocks based on their type
	for _, block := range stats.Blocks {
		l := prometheus.Labels{"server": block.Server, "share": block.Share}

		switch block.BlockType {
		case cifs.BlockTypeSMB1:
			// SMB1/2 legacy format - 22 metrics
			if len(block.Metrics) < 22 {
				continue
			}
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_smb", "Total SMB", nil, l), prometheus.GaugeValue, float64(block.Metrics[0]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_oplocks", "Total oplock breaks", nil, l), prometheus.GaugeValue, float64(block.Metrics[1]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_reads", "Total reads", nil, l), prometheus.GaugeValue, float64(block.Metrics[2]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_read_bytes", "Total read bytes", nil, l), prometheus.GaugeValue, float64(block.Metrics[3]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_writes", "Total writes", nil, l), prometheus.GaugeValue, float64(block.Metrics[4]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_write_bytes", "Total write bytes", nil, l), prometheus.GaugeValue, float64(block.Metrics[5]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_flushes", "Total flushes", nil, l), prometheus.GaugeValue, float64(block.Metrics[6]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_locks", "Total locks", nil, l), prometheus.GaugeValue, float64(block.Metrics[7]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_hardlinks", "Total hardlinks", nil, l), prometheus.GaugeValue, float64(block.Metrics[8]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_symlinks", "Total symlinks", nil, l), prometheus.GaugeValue, float64(block.Metrics[9]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_opens", "Total opens", nil, l), prometheus.GaugeValue, float64(block.Metrics[10]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_closes", "Total closes", nil, l), prometheus.GaugeValue, float64(block.Metrics[11]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_deletes", "Total deletes", nil, l), prometheus.GaugeValue, float64(block.Metrics[12]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_posix_opens", "Total posix opens", nil, l), prometheus.GaugeValue, float64(block.Metrics[13]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_posix_mkdirs", "Total posix mkdirs", nil, l), prometheus.GaugeValue, float64(block.Metrics[14]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_mkdirs", "Total mkdirs", nil, l), prometheus.GaugeValue, float64(block.Metrics[15]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_rmdirs", "Total rmdirs", nil, l), prometheus.GaugeValue, float64(block.Metrics[16]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_renames", "Total renames", nil, l), prometheus.GaugeValue, float64(block.Metrics[17]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_t2_renames", "Total T2 renames", nil, l), prometheus.GaugeValue, float64(block.Metrics[18]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_find_first", "Total find first", nil, l), prometheus.GaugeValue, float64(block.Metrics[19]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_find_next", "Total find next", nil, l), prometheus.GaugeValue, float64(block.Metrics[20]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_find_close", "Total find close", nil, l), prometheus.GaugeValue, float64(block.Metrics[21]))

		case cifs.BlockTypeSMB3Legacy:
			// SMB3 legacy format (X sent Y failed) - 39 metrics
			if len(block.Metrics) < 39 {
				continue
			}
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_smb", "Total SMB", nil, l), prometheus.GaugeValue, float64(block.Metrics[0]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_negotiates_sent", "Total negotiates sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[1]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_negotiates_failed", "Total negotiates failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[2]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_session_setups_sent", "Total session setups sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[3]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_session_setups_failed", "Total session setups failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[4]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_logoffs_sent", "Total logoffs sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[5]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_logoffs_failed", "Total logoffs failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[6]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_tree_connects_sent", "Total tree_connects sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[7]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_tree_connects_failed", "Total tree_connects failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[8]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_tree_disconnects_sent", "Total tree_disconnects sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[9]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_tree_disconnects_failed", "Total tree_disconnects failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[10]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_creates_sent", "Total creates sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[11]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_creates_failed", "Total creates failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[12]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_closes_sent", "Total closes sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[13]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_closes_failed", "Total closes failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[14]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_flushes_sent", "Total flushes sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[15]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_flushes_failed", "Total flushes failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[16]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_reads_sent", "Total reads sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[17]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_reads_failed", "Total reads failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[18]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_writes_sent", "Total writes sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[19]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_writes_failed", "Total writes failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[20]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_locks_sent", "Total locks sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[21]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_locks_failed", "Total locks failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[22]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_ioctls_sent", "Total ioctls sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[23]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_ioctls_failed", "Total ioctls failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[24]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_cancels_sent", "Total cancels sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[25]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_cancels_failed", "Total cancels failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[26]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_echos_sent", "Total echos sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[27]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_echos_failed", "Total echos failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[28]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_query_directories_sent", "Total query_directories sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[29]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_query_directories_failed", "Total query_directories failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[30]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_change_notifies_sent", "Total change_notifies sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[31]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_change_notifies_failed", "Total change_notifies failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[32]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_query_infos_sent", "Total query_infos sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[33]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_query_infos_failed", "Total query_infos failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[34]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_set_infos_sent", "Total set_infos sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[35]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_set_infos_failed", "Total set_infos failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[36]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_oplocks_sent", "Total oplocks breaks sent", nil, l), prometheus.GaugeValue, float64(block.Metrics[37]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_oplocks_failed", "Total oplocks breaks failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[38]))

		case cifs.BlockTypeSMB3Modern:
			// SMB3 modern format (X total Y failed) - 33 metrics
			// Order: SMBs, BytesRead, BytesWritten, OpenFilesLocal, OpenFilesServer,
			// then pairs of (total, failed) for: TreeConnects, TreeDisconnects, Creates, Closes,
			// Flushes, Reads, Writes, Locks, IOCTLs, QueryDirectories, ChangeNotifies,
			// QueryInfos, SetInfos, OplockBreaks
			if len(block.Metrics) < 33 {
				continue
			}

			// Add connection status metric
			connectedVal := float64(0)
			if block.Connected {
				connectedVal = 1
			}
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_connected", "Connection status (1=connected, 0=disconnected)", nil, l), prometheus.GaugeValue, connectedVal)

			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_smb", "Total SMB", nil, l), prometheus.GaugeValue, float64(block.Metrics[0]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_read_bytes", "Total read bytes", nil, l), prometheus.GaugeValue, float64(block.Metrics[1]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_write_bytes", "Total write bytes", nil, l), prometheus.GaugeValue, float64(block.Metrics[2]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_open_files_local", "Open files (local)", nil, l), prometheus.GaugeValue, float64(block.Metrics[3]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_open_files_server", "Open files on server", nil, l), prometheus.GaugeValue, float64(block.Metrics[4]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_tree_connects", "Total tree connects", nil, l), prometheus.GaugeValue, float64(block.Metrics[5]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_tree_connects_failed", "Total tree connects failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[6]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_tree_disconnects", "Total tree disconnects", nil, l), prometheus.GaugeValue, float64(block.Metrics[7]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_tree_disconnects_failed", "Total tree disconnects failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[8]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_creates", "Total creates", nil, l), prometheus.GaugeValue, float64(block.Metrics[9]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_creates_failed", "Total creates failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[10]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_closes", "Total closes", nil, l), prometheus.GaugeValue, float64(block.Metrics[11]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_closes_failed", "Total closes failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[12]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_flushes", "Total flushes", nil, l), prometheus.GaugeValue, float64(block.Metrics[13]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_flushes_failed", "Total flushes failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[14]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_reads", "Total reads", nil, l), prometheus.GaugeValue, float64(block.Metrics[15]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_reads_failed", "Total reads failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[16]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_writes", "Total writes", nil, l), prometheus.GaugeValue, float64(block.Metrics[17]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_writes_failed", "Total writes failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[18]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_locks", "Total locks", nil, l), prometheus.GaugeValue, float64(block.Metrics[19]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_locks_failed", "Total locks failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[20]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_ioctls", "Total ioctls", nil, l), prometheus.GaugeValue, float64(block.Metrics[21]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_ioctls_failed", "Total ioctls failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[22]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_query_directories", "Total query directories", nil, l), prometheus.GaugeValue, float64(block.Metrics[23]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_query_directories_failed", "Total query directories failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[24]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_change_notifies", "Total change notifies", nil, l), prometheus.GaugeValue, float64(block.Metrics[25]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_change_notifies_failed", "Total change notifies failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[26]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_query_infos", "Total query infos", nil, l), prometheus.GaugeValue, float64(block.Metrics[27]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_query_infos_failed", "Total query infos failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[28]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_set_infos", "Total set infos", nil, l), prometheus.GaugeValue, float64(block.Metrics[29]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_set_infos_failed", "Total set infos failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[30]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_oplocks", "Total oplock breaks", nil, l), prometheus.GaugeValue, float64(block.Metrics[31]))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("cifs_total_oplocks_failed", "Total oplock breaks failed", nil, l), prometheus.GaugeValue, float64(block.Metrics[32]))
			
			// Export per-share max requests in flight
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc("cifs_share_max_requests_in_flight", "Max concurrent requests in flight per share", nil, l),
				prometheus.GaugeValue,
				float64(block.MaxRequestsInFlight),
			)
			
			// Export per-share timing stats
			for _, ct := range block.Timings {
				tl := prometheus.Labels{
					"server":  block.Server,
					"share":   block.Share,
					"command": fmt.Sprintf("%d", ct.Command),
				}
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc("cifs_share_request_latency_max_seconds", "Maximum request latency per share/command in seconds", nil, tl),
					prometheus.GaugeValue,
					float64(ct.Slowest)/100.0,
				)
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc("cifs_share_request_latency_min_seconds", "Minimum request latency per share/command in seconds", nil, tl),
					prometheus.GaugeValue,
					float64(ct.Fastest)/100.0,
				)
				avgLatency := float64(0)
				if ct.Count > 0 {
					avgLatency = float64(ct.TotalTime) / float64(ct.Count) / 100.0
				}
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc("cifs_share_request_latency_avg_seconds", "Average request latency per share/command in seconds", nil, tl),
					prometheus.GaugeValue,
					avgLatency,
				)
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc("cifs_share_request_count", "Request count per share/command", nil, tl),
					prometheus.GaugeValue,
					float64(ct.Count),
				)
			}
		}
	}

	// Export slow responses - key leading indicator for connection problems
	for _, sr := range stats.SlowResponses {
		l := prometheus.Labels{
			"server":  sr.Server,
			"command": fmt.Sprintf("%d", sr.Command),
		}
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("cifs_slow_responses", "Slow responses from server (leading indicator for disconnects)", nil, l),
			prometheus.GaugeValue,
			float64(sr.Count),
		)
	}

	// Export command timing stats - response time metrics for latency monitoring
	// Time is in jiffies (100 per second), so divide by 100 to get seconds
	for _, ct := range stats.CommandTimings {
		l := prometheus.Labels{
			"command": fmt.Sprintf("%d", ct.Command),
		}
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("cifs_request_latency_max_seconds", "Maximum (slowest) request latency per command in seconds", nil, l),
			prometheus.GaugeValue,
			float64(ct.Slowest)/100.0, // Convert jiffies to seconds
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("cifs_request_latency_min_seconds", "Minimum (fastest) request latency per command in seconds", nil, l),
			prometheus.GaugeValue,
			float64(ct.Fastest)/100.0, // Convert jiffies to seconds
		)
		// Average latency = total time / count
		avgLatency := float64(0)
		if ct.Count > 0 {
			avgLatency = float64(ct.TotalTime) / float64(ct.Count) / 100.0
		}
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("cifs_request_latency_avg_seconds", "Average request latency per command in seconds", nil, l),
			prometheus.GaugeValue,
			avgLatency,
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("cifs_request_count", "Total number of requests per command", nil, l),
			prometheus.GaugeValue,
			float64(ct.Count),
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("cifs_request_total_time_seconds", "Total time spent processing requests per command in seconds", nil, l),
			prometheus.GaugeValue,
			float64(ct.TotalTime)/100.0, // Convert jiffies to seconds
		)
	}
}
