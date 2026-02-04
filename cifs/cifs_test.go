package cifs

import (
	"strings"
	"testing"
)

const legacySMB1Input = `Resources in use
CIFS Session: 1
Share (unique mount targets): 2
SMB Request/Response Buffer: 1 Pool size: 5
SMB Small Req/Resp Buffer: 1 Pool size: 30
Operations (MIDs): 0

0 session 0 share reconnects
Total vfs operations: 16 maximum at one time: 2

1) \\server1\share1
SMBs: 9 Oplocks breaks: 0
Reads:  0 Bytes: 0
Writes: 0 Bytes: 0
Flushes: 0
Locks: 0 HardLinks: 0 Symlinks: 0
Opens: 0 Closes: 0 Deletes: 0
Posix Opens: 0 Posix Mkdirs: 0
Mkdirs: 0 Rmdirs: 0
Renames: 0 T2 Renames 0
FindFirst: 1 FNext 0 FClose 0
`

const legacySMB3Input = `Resources in use
CIFS Session: 1
Share (unique mount targets): 1
SMB Request/Response Buffer: 1 Pool size: 5
SMB Small Req/Resp Buffer: 1 Pool size: 30
Operations (MIDs): 0

0 session 0 share reconnects
Total vfs operations: 16 maximum at one time: 2

1) \\server2\share2
SMBs: 20
Negotiates: 0 sent 0 failed
SessionSetups: 0 sent 0 failed
Logoffs: 0 sent 0 failed
TreeConnects: 0 sent 0 failed
TreeDisconnects: 0 sent 0 failed
Creates: 0 sent 2 failed
Closes: 0 sent 0 failed
Flushes: 0 sent 0 failed
Reads: 0 sent 0 failed
Writes: 0 sent 0 failed
Locks: 0 sent 0 failed
IOCTLs: 0 sent 0 failed
Cancels: 0 sent 0 failed
Echos: 0 sent 0 failed
QueryDirectories: 0 sent 0 failed
ChangeNotifies: 0 sent 0 failed
QueryInfos: 0 sent 0 failed
SetInfos: 0 sent 0 failed
OplockBreaks: 0 sent 0 failed
`

const modernSMB3Input = `Resources in use
CIFS Session: 1
Share (unique mount targets): 2
SMB Request/Response Buffer: 1 Pool size: 5
SMB Small Req/Resp Buffer: 1 Pool size: 30
Operations (MIDs): 0

0 session 0 share reconnects
Total vfs operations: 16 maximum at one time: 2

1) \\smb157.boreal-system.svc.cluster.local\Ddrive$
SMBs: 195697
Bytes read: 3407203268  Bytes written: 1908651680
Open files: 12 total (local), 0 open on server
TreeConnects: 1709 total 0 failed
TreeDisconnects: 5 total 0 failed
Creates: 100 total 2 failed
Closes: 98 total 0 failed
Flushes: 10 total 0 failed
Reads: 5000 total 5 failed
Writes: 3000 total 3 failed
Locks: 50 total 0 failed
IOCTLs: 25 total 0 failed
QueryDirectories: 200 total 0 failed
ChangeNotifies: 15 total 0 failed
QueryInfos: 1000 total 0 failed
SetInfos: 500 total 0 failed
OplockBreaks: 4 sent 4 failed

2) \\fileserver.example.com\Share1 CONNECTED
SMBs: 50000
Bytes read: 1234567890  Bytes written: 987654321
Open files: 5 total (local), 3 open on server
TreeConnects: 500 total 0 failed
TreeDisconnects: 2 total 0 failed
Creates: 50 total 0 failed
Closes: 48 total 0 failed
Flushes: 5 total 0 failed
Reads: 2500 total 0 failed
Writes: 1500 total 0 failed
Locks: 25 total 0 failed
IOCTLs: 10 total 0 failed
QueryDirectories: 100 total 0 failed
ChangeNotifies: 8 total 0 failed
QueryInfos: 500 total 0 failed
SetInfos: 250 total 0 failed
OplockBreaks: 0 sent 0 failed
`

func TestParseLegacySMB1(t *testing.T) {
	stats, err := ParseClientStats(strings.NewReader(legacySMB1Input))
	if err != nil {
		t.Fatalf("Failed to parse legacy SMB1 input: %v", err)
	}

	if len(stats.Blocks) != 1 {
		t.Fatalf("Expected 1 block, got %d", len(stats.Blocks))
	}

	block := stats.Blocks[0]
	if block.BlockType != BlockTypeSMB1 {
		t.Errorf("Expected BlockTypeSMB1, got %v", block.BlockType)
	}
	if block.Server != "server1" {
		t.Errorf("Expected server 'server1', got '%s'", block.Server)
	}
	if block.Share != "\\share1" {
		t.Errorf("Expected share '\\share1', got '%s'", block.Share)
	}
	if len(block.Metrics) != 22 {
		t.Errorf("Expected 22 metrics, got %d", len(block.Metrics))
	}
	// Check SMBs value
	if block.Metrics[0] != 9 {
		t.Errorf("Expected SMBs=9, got %d", block.Metrics[0])
	}
}

func TestParseLegacySMB3(t *testing.T) {
	stats, err := ParseClientStats(strings.NewReader(legacySMB3Input))
	if err != nil {
		t.Fatalf("Failed to parse legacy SMB3 input: %v", err)
	}

	if len(stats.Blocks) != 1 {
		t.Fatalf("Expected 1 block, got %d", len(stats.Blocks))
	}

	block := stats.Blocks[0]
	if block.BlockType != BlockTypeSMB3Legacy {
		t.Errorf("Expected BlockTypeSMB3Legacy, got %v", block.BlockType)
	}
	if block.Server != "server2" {
		t.Errorf("Expected server 'server2', got '%s'", block.Server)
	}
	if block.Share != "\\share2" {
		t.Errorf("Expected share '\\share2', got '%s'", block.Share)
	}
	if len(block.Metrics) != 39 {
		t.Errorf("Expected 39 metrics, got %d", len(block.Metrics))
	}
	// Check SMBs value
	if block.Metrics[0] != 20 {
		t.Errorf("Expected SMBs=20, got %d", block.Metrics[0])
	}
}

func TestParseModernSMB3(t *testing.T) {
	stats, err := ParseClientStats(strings.NewReader(modernSMB3Input))
	if err != nil {
		t.Fatalf("Failed to parse modern SMB3 input: %v", err)
	}

	if len(stats.Blocks) != 2 {
		t.Fatalf("Expected 2 blocks, got %d", len(stats.Blocks))
	}

	// First block - no status (defaults to connected/true - only explicit DISCONNECTED is false)
	block1 := stats.Blocks[0]
	if block1.BlockType != BlockTypeSMB3Modern {
		t.Errorf("Block 1: Expected BlockTypeSMB3Modern, got %v", block1.BlockType)
	}
	if block1.Server != "smb157.boreal-system.svc.cluster.local" {
		t.Errorf("Block 1: Expected server 'smb157.boreal-system.svc.cluster.local', got '%s'", block1.Server)
	}
	if block1.Share != "\\Ddrive$" {
		t.Errorf("Block 1: Expected share '\\Ddrive$', got '%s'", block1.Share)
	}
	if !block1.Connected {
		t.Errorf("Block 1: Expected Connected=true (no status means connected), got false")
	}
	// Check SMBs value
	if block1.Metrics[0] != 195697 {
		t.Errorf("Block 1: Expected SMBs=195697, got %d", block1.Metrics[0])
	}
	// Check Bytes read
	if block1.Metrics[1] != 3407203268 {
		t.Errorf("Block 1: Expected Bytes read=3407203268, got %d", block1.Metrics[1])
	}
	// Check Bytes written
	if block1.Metrics[2] != 1908651680 {
		t.Errorf("Block 1: Expected Bytes written=1908651680, got %d", block1.Metrics[2])
	}

	// Second block - CONNECTED
	block2 := stats.Blocks[1]
	if block2.BlockType != BlockTypeSMB3Modern {
		t.Errorf("Block 2: Expected BlockTypeSMB3Modern, got %v", block2.BlockType)
	}
	if block2.Server != "fileserver.example.com" {
		t.Errorf("Block 2: Expected server 'fileserver.example.com', got '%s'", block2.Server)
	}
	if !block2.Connected {
		t.Errorf("Block 2: Expected Connected=true, got false")
	}
}

// Test with actual kernel output format (with tabs, trailing spaces, timing data)
const realKernelOutput = `Resources in use
CIFS Session: 2
Share (unique mount targets): 4
SMB Request/Response Buffer: 7 Pool size: 6
SMB Small Req/Resp Buffer: 2 Pool size: 30
Total Large 79160 Small 513475 Allocations
Operations (MIDs): 0

1818 session 3543 share reconnects
Total vfs operations: 140410 maximum at one time: 148

Max requests in flight: 249
Total time spent processing by command. Time units are jiffies (100 per second)
  SMB3 CMD	Number	Total Time	Fastest	Slowest
  --------	------	----------	-------	-------
  0		1733	40702		2	1451
  88 slow responses from smb157.boreal-system.svc.cluster.local for command 0

1) \\smb157.boreal-system.svc.cluster.local\Ddrive$	DISCONNECTED 
SMBs: 195835
Bytes read: 3407203268  Bytes written: 1908651680
Open files: 12 total (local), 0 open on server
TreeConnects: 1738 total 0 failed
TreeDisconnects: 0 total 0 failed
Creates: 57309 total 10 failed
Closes: 56736 total 40 failed
Flushes: 25 total 0 failed
Reads: 14171 total 63 failed
Writes: 850 total 59 failed
Locks: 0 total 0 failed
IOCTLs: 9028 total 6 failed
QueryDirectories: 6973 total 3 failed
ChangeNotifies: 0 total 0 failed
QueryInfos: 48965 total 19 failed
SetInfos: 41 total 0 failed
OplockBreaks: 4 sent 4 failed
Max requests in flight: 95
Total time spent processing by command.

2) \\smb161.boreal-system.svc.cluster.local\Edrive$	DISCONNECTED 
SMBs: 61736
Bytes read: 1284821557  Bytes written: 1029407275
Open files: 0 total (local), 1 open on server
TreeConnects: 39 total 0 failed
TreeDisconnects: 0 total 0 failed
Creates: 19052 total 13 failed
Closes: 18809 total 16 failed
Flushes: 38 total 0 failed
Reads: 1769 total 30 failed
Writes: 285 total 24 failed
Locks: 0 total 0 failed
IOCTLs: 1200 total 6 failed
QueryDirectories: 3825 total 20 failed
ChangeNotifies: 0 total 0 failed
QueryInfos: 16652 total 1 failed
SetInfos: 67 total 0 failed
OplockBreaks: 0 sent 0 failed
`

func TestParseRealKernelOutput(t *testing.T) {
	stats, err := ParseClientStats(strings.NewReader(realKernelOutput))
	if err != nil {
		t.Fatalf("Failed to parse real kernel output: %v", err)
	}

	t.Logf("Parsed %d blocks", len(stats.Blocks))
	for i, block := range stats.Blocks {
		t.Logf("Block %d: Server=%s, Share=%s, Type=%v, Metrics=%d", 
			i, block.Server, block.Share, block.BlockType, len(block.Metrics))
	}

	if len(stats.Blocks) != 2 {
		t.Errorf("Expected 2 blocks, got %d", len(stats.Blocks))
	}

	if len(stats.Blocks) > 0 {
		block := stats.Blocks[0]
		if block.Server != "smb157.boreal-system.svc.cluster.local" {
			t.Errorf("Expected server 'smb157.boreal-system.svc.cluster.local', got '%s'", block.Server)
		}
		if block.Metrics[0] != 195835 {
			t.Errorf("Expected SMBs=195835, got %d", block.Metrics[0])
		}
	}
}

const slowResponsesInput = `Resources in use
CIFS Session: 1
Share (unique mount targets): 1
SMB Request/Response Buffer: 1 Pool size: 5
SMB Small Req/Resp Buffer: 1 Pool size: 30
Operations (MIDs): 0

0 session 0 share reconnects
Total vfs operations: 16 maximum at one time: 2

Max requests in flight: 249
  88 slow responses from smb157.boreal-system.svc.cluster.local for command 0
  165 slow responses from smb157.boreal-system.svc.cluster.local for command 1
  28100 slow responses from smb157.boreal-system.svc.cluster.local for command 5
  13 slow responses from smb161.boreal-system.svc.cluster.local for command 0
`

func TestParseSlowResponses(t *testing.T) {
	stats, err := ParseClientStats(strings.NewReader(slowResponsesInput))
	if err != nil {
		t.Fatalf("Failed to parse slow responses input: %v", err)
	}

	t.Logf("Parsed %d slow responses", len(stats.SlowResponses))
	for _, sr := range stats.SlowResponses {
		t.Logf("SlowResponse: Server=%s, Command=%d, Count=%d", sr.Server, sr.Command, sr.Count)
	}

	if len(stats.SlowResponses) != 4 {
		t.Errorf("Expected 4 slow response entries, got %d", len(stats.SlowResponses))
	}

	if len(stats.SlowResponses) >= 3 {
		// Check third entry (28100 slow responses for command 5)
		sr := stats.SlowResponses[2]
		if sr.Server != "smb157.boreal-system.svc.cluster.local" {
			t.Errorf("Expected server 'smb157.boreal-system.svc.cluster.local', got '%s'", sr.Server)
		}
		if sr.Command != 5 {
			t.Errorf("Expected command 5, got %d", sr.Command)
		}
		if sr.Count != 28100 {
			t.Errorf("Expected count 28100, got %d", sr.Count)
		}
	}
}

func TestParseHeader(t *testing.T) {
	stats, err := ParseClientStats(strings.NewReader(modernSMB3Input))
	if err != nil {
		t.Fatalf("Failed to parse input: %v", err)
	}

	if stats.Header.CIFSSession != 1 {
		t.Errorf("Expected CIFSSession=1, got %d", stats.Header.CIFSSession)
	}
	if stats.Header.Targets != 2 {
		t.Errorf("Expected Targets=2, got %d", stats.Header.Targets)
	}
	if stats.Header.MaxOp != 16 {
		t.Errorf("Expected MaxOp=16, got %d", stats.Header.MaxOp)
	}
	if stats.Header.AtOnce != 2 {
		t.Errorf("Expected AtOnce=2, got %d", stats.Header.AtOnce)
	}
}
