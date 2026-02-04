package cifs

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
)

// ClientStats describes our CIFS statistics file.
type ClientStats struct {
	Header         Header
	Blocks         []*Block
	SlowResponses  []SlowResponse
	CommandTimings []CommandTiming
}

// SlowResponse stores slow response counts per server/command
type SlowResponse struct {
	Server  string
	Command uint64
	Count   uint64
}

// CommandTiming stores timing stats per SMB command
type CommandTiming struct {
	Command   uint64
	Count     uint64 // Number of operations
	TotalTime uint64 // Total time in jiffies (100/sec)
	Fastest   uint64 // Fastest response in jiffies
	Slowest   uint64 // Slowest response in jiffies
}

// BlockType indicates the type/version of SMB stats block
type BlockType int

const (
	BlockTypeSMB1       BlockType = iota // Legacy SMB1/2 format
	BlockTypeSMB3Legacy                  // Legacy SMB3 format (X sent Y failed)
	BlockTypeSMB3Modern                  // Modern SMB3 format (X total Y failed)
)

// Block stores each block with server, share and all metrics.
// Server and share are useful for labeling.
type Block struct {
	Server              string
	Share               string
	Metrics             []uint64
	BlockType           BlockType         // Type of block (SMB1, SMB3Legacy, SMB3Modern)
	Connected           bool              // Connection status (only for SMB3Modern)
	Timings             []CommandTiming   // Per-share command timing stats
	MaxRequestsInFlight uint64            // Per-share max concurrent requests
}

// Header stores all header information from the CIFS header.
// A []uint64 slice would be maybe a better solution...
// At least as long slices are ordered. We could use the same approach as for the metrics in block.
type Header struct {
	CIFSSession        uint64
	Targets            uint64
	SMBReq             uint64
	SMBBuf             uint64
	SMBSmallReq        uint64
	SMBSmallBuf        uint64
	Op                 uint64
	Session            uint64
	ShareReconnects    uint64
	MaxOp              uint64
	AtOnce             uint64
	MaxRequestsInFlight uint64
}

// This is our multiline regex for the SMB blocks.
// We can possibly get rid of the named regex groups.

// Legacy SMB1/2 format regex
var reSMB1 = regexp.MustCompile(`(?m)(?P<SMBID>\d+)\) \\\\(?P<Server>[A-Za-z0-9_.-]+)(?P<Share>[^\n]+)\nSMBs:\s+(?P<SMB>\d+) Oplocks breaks:\s+(?P<OpLocks>\d+)\nReads:\s+(?P<Reads>\d+) Bytes:\s+(?P<ReadsBytes>\d+)\nWrites:\s+(?P<Writes>\d+) Bytes:\s+(?P<WritesBytes>\d+)\nFlushes:\s+(?P<Flushes>\d+)\nLocks:\s+(?P<Locks>\d+) HardLinks:\s+(?P<Hardlinks>\d+) Symlinks:\s+(?P<Symlinks>\d+)\nOpens:\s+(?P<Opens>\d+) Closes:\s+(?P<Closes>\d+) Deletes:\s+(?P<Deletes>\d+)\nPosix Opens:\s+(?P<PosixOpens>\d+) Posix Mkdirs:\s+(?P<PosixMkdirs>\d+)\nMkdirs:\s+(?P<Mkdirs>\d+) Rmdirs:\s+(?P<Rmdirs>\d+)\nRenames:\s+(?P<Renames>\d+) T2 Renames\s+(?P<T2Renames>\d+)\nFindFirst:\s+(?P<FindFirst>\d+) FNext\s+(?P<FNext>\d+) FClose\s+(?P<FClose>\d+)`)

// Legacy SMB3 format regex (X sent Y failed format)
var reSMB3Legacy = regexp.MustCompile(`(?m)(?P<SMB3ID>\d+)\) \\\\(?P<SMB3Server>[A-Za-z0-9_.-]+)(?P<SMB3Share>[^\n]+)\nSMBs:\s+(?P<SMB3>\d+)\nNegotiates:\s+(?P<NegotiatesSent>\d+) sent\s+(?P<NegotiatesFailed>\d+) failed\nSessionSetups:\s+(?P<SessionSetupsSent>\d+) sent\s+(?P<SessionSetupsFailed>\d+) failed\nLogoffs:\s+(?P<LogoffsSent>\d+) sent\s+(?P<LogoffsFailed>\d+) failed\nTreeConnects:\s+(?P<TreeConnectsSent>\d+) sent\s+(?P<TreeConnectsFailed>\d+) failed\nTreeDisconnects:\s+(?P<TreeDisconnectsSent>\d+) sent\s+(?P<TreeDisconnectsFailed>\d+) failed\nCreates:\s+(?P<CreatesSent>\d+) sent\s+(?P<CreatesFailed>\d+) failed\nCloses:\s+(?P<ClosesSent>\d+) sent\s+(?P<ClosesFailed>\d+) failed\nFlushes:\s+(?P<FlushesSent>\d+) sent\s+(?P<FlushesFailed>\d+) failed\nReads:\s+(?P<ReadsSent>\d+) sent\s+(?P<ReadsFailed>\d+) failed\nWrites:\s+(?P<WritesSent>\d+) sent\s+(?P<WritesFailed>\d+) failed\nLocks:\s+(?P<LocksSent>\d+) sent\s+(?P<LocksFailed>\d+) failed\nIOCTLs:\s+(?P<IOCTLsSent>\d+) sent\s+(?P<IOCTLsFailed>\d+) failed\nCancels:\s+(?P<CancelsSent>\d+) sent\s+(?P<CancelsFailed>\d+) failed\nEchos:\s+(?P<EchosSent>\d+) sent\s+(?P<EchosFailed>\d+) failed\nQueryDirectories:\s+(?P<QueryDirectoriesSent>\d+) sent\s+(?P<QueryDirectoriesFailed>\d+) failed\nChangeNotifies:\s+(?P<ChangeNotifiesSent>\d+) sent\s+(?P<ChangeNotifiesFailed>\d+) failed\nQueryInfos:\s+(?P<QueryInfosSent>\d+) sent\s+(?P<QueryInfosFailed>\d+) failed\nSetInfos:\s+(?P<SetInfosSent>\d+) sent\s+(?P<SetInfosFailed>\d+) failed\nOplockBreaks:\s+(?P<OpLockBreaksSent>\d+) sent\s+(?P<OpLockBreaksFailed>\d+) failed`)

// Modern kernel SMB3 format regex (X total Y failed format, with optional CONNECTED/DISCONNECTED status)
// This matches the format from newer kernels (5.x+) which changed the stats output
// Note: Status may or may not be present; OplockBreaks uses "sent" not "total"
var reSMB3Modern = regexp.MustCompile(`(?m)(?P<SMB3ID>\d+)\) \\\\(?P<SMB3Server>[A-Za-z0-9_.-]+)(?P<SMB3Share>[^\s\n]+)(?:\s+(?P<Status>CONNECTED|DISCONNECTED))?\s*\nSMBs:\s+(?P<SMB3>\d+)\nBytes read:\s+(?P<BytesRead>\d+)\s+Bytes written:\s+(?P<BytesWritten>\d+)\nOpen files:\s+(?P<OpenFilesLocal>\d+) total \(local\),\s+(?P<OpenFilesServer>\d+) open on server\nTreeConnects:\s+(?P<TreeConnectsTotal>\d+) total\s+(?P<TreeConnectsFailed>\d+) failed\nTreeDisconnects:\s+(?P<TreeDisconnectsTotal>\d+) total\s+(?P<TreeDisconnectsFailed>\d+) failed\nCreates:\s+(?P<CreatesTotal>\d+) total\s+(?P<CreatesFailed>\d+) failed\nCloses:\s+(?P<ClosesTotal>\d+) total\s+(?P<ClosesFailed>\d+) failed\nFlushes:\s+(?P<FlushesTotal>\d+) total\s+(?P<FlushesFailed>\d+) failed\nReads:\s+(?P<ReadsTotal>\d+) total\s+(?P<ReadsFailed>\d+) failed\nWrites:\s+(?P<WritesTotal>\d+) total\s+(?P<WritesFailed>\d+) failed\nLocks:\s+(?P<LocksTotal>\d+) total\s+(?P<LocksFailed>\d+) failed\nIOCTLs:\s+(?P<IOCTLsTotal>\d+) total\s+(?P<IOCTLsFailed>\d+) failed\nQueryDirectories:\s+(?P<QueryDirectoriesTotal>\d+) total\s+(?P<QueryDirectoriesFailed>\d+) failed\nChangeNotifies:\s+(?P<ChangeNotifiesTotal>\d+) total\s+(?P<ChangeNotifiesFailed>\d+) failed\nQueryInfos:\s+(?P<QueryInfosTotal>\d+) total\s+(?P<QueryInfosFailed>\d+) failed\nSetInfos:\s+(?P<SetInfosTotal>\d+) total\s+(?P<SetInfosFailed>\d+) failed\nOplockBreaks:\s+(?P<OpLockBreaksSent>\d+) sent\s+(?P<OpLockBreaksFailed>\d+) failed`)

// Regex for slow responses: "88 slow responses from server.example.com for command 0"
var reSlowResponses = regexp.MustCompile(`(?m)^\s*(\d+) slow responses from ([A-Za-z0-9_.-]+) for command (\d+)`)

// Regex for max requests in flight (global): "Max requests in flight: 249"
var reMaxRequestsGlobal = regexp.MustCompile(`(?m)^Max requests in flight:\s+(\d+)`)

// Regex for command timing stats: "  0		1733	40702		2	1451"
// Format: command, count, total_time, fastest, slowest (tab-separated)
var reCommandTiming = regexp.MustCompile(`(?m)^\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$`)

// Regex to find share block start positions for associating timing data
var reShareBlockStart = regexp.MustCompile(`(?m)^\d+\) \\\\([A-Za-z0-9_.-]+)\\([^\s\n]+)`)

// NewClientStats opens the cifs stats file and returns our parsed CIFS client statistics.
func NewClientStats() (*ClientStats, error) {
	f, err := os.Open("/proc/fs/cifs/Stats")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseClientStats(f)
}

// parseHeader uses fmt.Sscanf() for matching all information in the header.
// I hope this approach is faster than using a multiline regex for the header.
func (stats *ClientStats) parseHeader(line string) {
	if _, err := fmt.Sscanf(line, "CIFS Session: %d", &stats.Header.CIFSSession); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "Share (unique mount targets): %d", &stats.Header.Targets); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "SMB Request/Response Buffer: %d Pool size: %d", &stats.Header.SMBReq, &stats.Header.SMBBuf); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "SMB Small Req/Resp Buffer: %d Pool size: %d", &stats.Header.SMBSmallReq, &stats.Header.SMBSmallBuf); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "Operations (MIDs): %d", &stats.Header.Op); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "%d session %d share reconnects", &stats.Header.Session, &stats.Header.ShareReconnects); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "Total vfs operations: %d maximum at one time: %d", &stats.Header.MaxOp, &stats.Header.AtOnce); err == nil {
		return
	}
}

// parseMaxRequestsInFlight extracts the global max requests in flight
func (stats *ClientStats) parseMaxRequestsInFlight(file string) {
	matches := reMaxRequestsGlobal.FindStringSubmatch(file)
	if len(matches) >= 2 {
		if val, err := strconv.ParseUint(matches[1], 10, 64); err == nil {
			stats.Header.MaxRequestsInFlight = val
		}
	}
}

// parseCommandTimings extracts global command timing statistics (first occurrence only)
// Format: command, count, total_time, fastest, slowest (in jiffies, 100/sec)
func (stats *ClientStats) parseCommandTimings(file string) {
	// Find where share blocks start to know where global stats end
	shareStarts := reShareBlockStart.FindAllStringIndex(file, -1)
	
	var globalSection string
	if len(shareStarts) > 0 {
		globalSection = file[:shareStarts[0][0]]
	} else {
		globalSection = file
	}
	
	matches := reCommandTiming.FindAllStringSubmatch(globalSection, -1)
	for _, match := range matches {
		cmd, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			continue
		}
		
		count, _ := strconv.ParseUint(match[2], 10, 64)
		totalTime, _ := strconv.ParseUint(match[3], 10, 64)
		fastest, _ := strconv.ParseUint(match[4], 10, 64)
		slowest, _ := strconv.ParseUint(match[5], 10, 64)
		
		stats.CommandTimings = append(stats.CommandTimings, CommandTiming{
			Command:   cmd,
			Count:     count,
			TotalTime: totalTime,
			Fastest:   fastest,
			Slowest:   slowest,
		})
	}
}

// parseMaxRequestsForSection extracts max requests in flight from a section
func parseMaxRequestsForSection(section string) uint64 {
	matches := reMaxRequestsGlobal.FindStringSubmatch(section)
	if len(matches) >= 2 {
		if val, err := strconv.ParseUint(matches[1], 10, 64); err == nil {
			return val
		}
	}
	return 0
}

// parseTimingsForSection extracts timing data from a section of the file
func parseTimingsForSection(section string) []CommandTiming {
	var timings []CommandTiming
	matches := reCommandTiming.FindAllStringSubmatch(section, -1)
	
	for _, match := range matches {
		cmd, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			continue
		}
		
		count, _ := strconv.ParseUint(match[2], 10, 64)
		totalTime, _ := strconv.ParseUint(match[3], 10, 64)
		fastest, _ := strconv.ParseUint(match[4], 10, 64)
		slowest, _ := strconv.ParseUint(match[5], 10, 64)
		
		timings = append(timings, CommandTiming{
			Command:   cmd,
			Count:     count,
			TotalTime: totalTime,
			Fastest:   fastest,
			Slowest:   slowest,
		})
	}
	return timings
}

// parseSlowResponses extracts slow response counts from the stats file
// Format: "88 slow responses from server.example.com for command 0"
func (stats *ClientStats) parseSlowResponses(file string) {
	matches := reSlowResponses.FindAllStringSubmatch(file, -1)
	for _, match := range matches {
		count, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			continue
		}
		command, err := strconv.ParseUint(match[3], 10, 64)
		if err != nil {
			continue
		}
		stats.SlowResponses = append(stats.SlowResponses, SlowResponse{
			Server:  match[2],
			Command: command,
			Count:   count,
		})
	}
}

// parseSMBBlocks uses multiline regexes for matching all SMB blocks.
// It tries to match against three formats:
// 1. SMB1/2 legacy format
// 2. SMB3 legacy format (X sent Y failed)
// 3. SMB3 modern format (X total Y failed, with CONNECTED/DISCONNECTED status)
func (stats *ClientStats) parseSMBBlocks(file string) {
	// Try SMB1/2 legacy format
	matches := reSMB1.FindAllStringSubmatch(file, -1)
	for _, match := range matches {
		block := &Block{
			Server:    match[2], // Server group
			Share:     match[3], // Share group
			Metrics:   []uint64{},
			BlockType: BlockTypeSMB1,
		}
		// Metrics start at index 4 (after ID, Server, Share)
		for i := 4; i < len(match); i++ {
			m, err := strconv.ParseUint(match[i], 10, 64)
			if err != nil {
				break
			}
			block.Metrics = append(block.Metrics, m)
		}
		stats.Blocks = append(stats.Blocks, block)
	}

	// Try SMB3 legacy format (X sent Y failed)
	matches = reSMB3Legacy.FindAllStringSubmatch(file, -1)
	for _, match := range matches {
		block := &Block{
			Server:    match[2], // Server group
			Share:     match[3], // Share group
			Metrics:   []uint64{},
			BlockType: BlockTypeSMB3Legacy,
		}
		// Metrics start at index 4 (after ID, Server, Share)
		for i := 4; i < len(match); i++ {
			m, err := strconv.ParseUint(match[i], 10, 64)
			if err != nil {
				break
			}
			block.Metrics = append(block.Metrics, m)
		}
		stats.Blocks = append(stats.Blocks, block)
	}

	// Try SMB3 modern format (X total Y failed)
	// Also find positions for extracting per-share timing data
	matchIndices := reSMB3Modern.FindAllStringSubmatchIndex(file, -1)
	matches = reSMB3Modern.FindAllStringSubmatch(file, -1)
	
	for i, match := range matches {
		block := &Block{
			Server:    match[2], // Server group
			Share:     match[3], // Share group
			Metrics:   []uint64{},
			BlockType: BlockTypeSMB3Modern,
		}
		// Capture connection status if present (match[4])
		// If status is empty or "CONNECTED", the share is connected
		// Only explicit "DISCONNECTED" means disconnected
		if match[4] != "DISCONNECTED" {
			block.Connected = true
		}
		// Metrics start at index 5 (after ID, Server, Share, Status)
		for j := 5; j < len(match); j++ {
			m, err := strconv.ParseUint(match[j], 10, 64)
			if err != nil {
				break
			}
			block.Metrics = append(block.Metrics, m)
		}
		
		// Extract timing data and max requests for this share
		// The data appears after the OplockBreaks line until the next share or EOF
		if i < len(matchIndices) {
			startIdx := matchIndices[i][1] // End of this match
			var endIdx int
			if i+1 < len(matchIndices) {
				endIdx = matchIndices[i+1][0] // Start of next match
			} else {
				endIdx = len(file) // End of file
			}
			section := file[startIdx:endIdx]
			block.Timings = parseTimingsForSection(section)
			block.MaxRequestsInFlight = parseMaxRequestsForSection(section)
		}
		
		stats.Blocks = append(stats.Blocks, block)
	}
}

// ParseClientstats scans the CIFS statistics file for the header and breaks.
// Then it scans the rest of the file and calls parseSMBBlocks for the multiline regex for
// matching all SMB blocks.
func ParseClientStats(r io.Reader) (*ClientStats, error) {
	stats := &ClientStats{}
	scanner := bufio.NewScanner(r)
	// parse Header
	headerLen := 9
	for scanner.Scan() {
		if headerLen == 0 {
			break
		}
		line := scanner.Text()
		stats.parseHeader(line)
		headerLen--
	}
	// construct SMB block file
	var file string
	for scanner.Scan() {
		line := scanner.Text()
		// We need to add a newline here, otherwise we will end up with one line and our
		// multiline regex will not match.
		file += line + "\n"
	}
	stats.parseSMBBlocks(file)
	stats.parseSlowResponses(file)
	stats.parseMaxRequestsInFlight(file)
	stats.parseCommandTimings(file)
	return stats, nil
}
