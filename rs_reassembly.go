package nebula

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/header"
)

const (
	// MaxReassemblyBuffers is the maximum number of concurrent reassembly sessions.
	// Bounded to prevent DoS from spoofed chunk headers.
	MaxReassemblyBuffers = 256

	// ReassemblyTimeout is how long a partial reassembly buffer lives before expiry.
	// Aligned with the handshake retry interval (100ms * 10 retries = 1s typical).
	ReassemblyTimeout = 5 * time.Second
)

// reassemblyKey uniquely identifies a reassembly session.
type reassemblyKey struct {
	handshakeID uint32
	noiseMsgNum uint8
}

// reassemblyBuffer holds chunks for a single handshake message being reassembled.
type reassemblyBuffer struct {
	shards      [][]byte // Indexed by chunk_idx; nil = not yet received
	totalChunks int
	dataShards  int
	received    int       // Number of non-nil shards received
	created     time.Time // For expiry
}

// ReassemblyManager manages reassembly of chunked handshake messages.
type ReassemblyManager struct {
	mu      sync.Mutex
	buffers map[reassemblyKey]*reassemblyBuffer
	l       *logrus.Logger
}

// NewReassemblyManager creates a new ReassemblyManager.
func NewReassemblyManager(l *logrus.Logger) *ReassemblyManager {
	return &ReassemblyManager{
		buffers: make(map[reassemblyKey]*reassemblyBuffer),
		l:       l,
	}
}

// HandleChunk processes an incoming chunked handshake packet.
// If reassembly is complete, it returns the reconstructed full handshake message
// (with a proper Nebula header) and true. Otherwise returns nil and false.
//
// The via and origHeader parameters are used to reconstruct the Nebula header
// of the reassembled message.
func (rm *ReassemblyManager) HandleChunk(packet []byte, origHeader *header.H) ([]byte, bool) {
	if len(packet) < header.Len+header.ChunkHeaderLen {
		rm.l.WithField("packetLen", len(packet)).Debug("Chunked handshake packet too short")
		return nil, false
	}

	// Parse chunk header
	var ch header.ChunkHeader
	if err := ch.Parse(packet[header.Len:]); err != nil {
		rm.l.WithError(err).Debug("Failed to parse chunk header")
		return nil, false
	}

	// Validate chunk header fields
	if ch.TotalChunks == 0 || ch.DataShards == 0 || int(ch.DataShards) > int(ch.TotalChunks) {
		rm.l.WithField("chunkHeader", ch.String()).Debug("Invalid chunk header parameters")
		return nil, false
	}
	if ch.ChunkIdx >= ch.TotalChunks {
		rm.l.WithField("chunkHeader", ch.String()).Debug("ChunkIdx out of range")
		return nil, false
	}

	key := reassemblyKey{
		handshakeID: ch.HandshakeID,
		noiseMsgNum: ch.NoiseMsgNum,
	}

	// Extract shard data (everything after Nebula header + chunk header)
	shardData := packet[header.Len+header.ChunkHeaderLen:]

	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Expire old buffers before processing
	rm.expireLockedBuffers()

	buf, exists := rm.buffers[key]
	if !exists {
		// Check buffer limit
		if len(rm.buffers) >= MaxReassemblyBuffers {
			rm.l.Debug("Reassembly buffer limit reached, dropping chunk")
			return nil, false
		}

		// Create new buffer
		buf = &reassemblyBuffer{
			shards:      make([][]byte, ch.TotalChunks),
			totalChunks: int(ch.TotalChunks),
			dataShards:  int(ch.DataShards),
			created:     time.Now(),
		}
		rm.buffers[key] = buf
	}

	// Validate consistency: incoming chunk params must match buffer
	if int(ch.TotalChunks) != buf.totalChunks || int(ch.DataShards) != buf.dataShards {
		rm.l.WithField("chunkHeader", ch.String()).
			WithField("bufferTotal", buf.totalChunks).
			WithField("bufferDataShards", buf.dataShards).
			Debug("Chunk header parameters mismatch with existing buffer")
		return nil, false
	}

	// Store shard (ignore duplicates)
	idx := int(ch.ChunkIdx)
	if buf.shards[idx] == nil {
		shard := make([]byte, len(shardData))
		copy(shard, shardData)
		buf.shards[idx] = shard
		buf.received++
	}

	// Check if we have enough shards to reconstruct
	if buf.received < buf.dataShards {
		if rm.l.Level >= logrus.DebugLevel {
			rm.l.WithField("handshakeID", ch.HandshakeID).
				WithField("noiseMsgNum", ch.NoiseMsgNum).
				WithField("received", buf.received).
				WithField("needed", buf.dataShards).
				Debug("Chunk received, waiting for more")
		}
		return nil, false
	}

	// Attempt reconstruction
	payload, err := rsDecode(buf.shards, buf.dataShards, buf.totalChunks)
	if err != nil {
		rm.l.WithError(err).WithField("handshakeID", ch.HandshakeID).
			WithField("noiseMsgNum", ch.NoiseMsgNum).
			Error("RS reconstruction failed")
		// Remove the buffer to allow retry with fresh chunks
		delete(rm.buffers, key)
		return nil, false
	}

	// Clean up buffer
	delete(rm.buffers, key)

	// Reconstruct the full message: Nebula header + reconstructed payload.
	// Use HandshakeIXPSK0 subtype so the existing handshake processing works unchanged.
	msgCounter := uint64(1)
	if ch.NoiseMsgNum == 1 {
		msgCounter = 2
	}
	fullMsg := make([]byte, header.Len+len(payload))
	header.Encode(fullMsg[:header.Len], header.Version, header.Handshake, header.HandshakeIXPSK0,
		origHeader.RemoteIndex, msgCounter)
	copy(fullMsg[header.Len:], payload)

	rm.l.WithField("handshakeID", ch.HandshakeID).
		WithField("noiseMsgNum", ch.NoiseMsgNum).
		WithField("payloadLen", len(payload)).
		Info("Chunked handshake reassembled")

	return fullMsg, true
}

// expireLockedBuffers removes reassembly buffers that have timed out.
// Must be called with rm.mu held.
func (rm *ReassemblyManager) expireLockedBuffers() {
	now := time.Now()
	for key, buf := range rm.buffers {
		if now.Sub(buf.created) > ReassemblyTimeout {
			if rm.l.Level >= logrus.DebugLevel {
				rm.l.WithField("handshakeID", key.handshakeID).
					WithField("noiseMsgNum", key.noiseMsgNum).
					WithField("received", buf.received).
					WithField("needed", buf.dataShards).
					Debug("Reassembly buffer expired")
			}
			delete(rm.buffers, key)
		}
	}
}

// ExpireBuffers is the public interface for expiring old buffers.
// Can be called periodically from a timer.
func (rm *ReassemblyManager) ExpireBuffers() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.expireLockedBuffers()
}
