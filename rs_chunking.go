package nebula

import (
	"fmt"
	"net/netip"

	"github.com/klauspost/reedsolomon"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
)

const (
	// DefaultChunkPayloadSize is the maximum payload per chunk, chosen to fit
	// within the IPv6 minimum MTU of 1280 bytes after IP (40) + UDP (8) headers
	// plus the Nebula header (16) and chunk header (8).
	// 1280 - 40 - 8 - 16 - 8 = 1208, rounded down to 1200 for safety.
	DefaultChunkPayloadSize = 1200

	// DefaultDataShards is the number of data shards (k) for RS encoding.
	DefaultDataShards = 5

	// DefaultParityShards is the number of parity shards (m) for RS encoding.
	DefaultParityShards = 3

	// ChunkingThreshold is the message size above which RS chunking is applied.
	// Messages at or below this size are sent as single packets (backward compatible).
	ChunkingThreshold = DefaultChunkPayloadSize
)

// rsEncode splits a handshake message into RS-coded chunks. Each chunk includes
// the Nebula header (with HandshakeIXPSK0Chunked subtype) and a ChunkHeader.
//
// Parameters:
//   - msg: the complete Noise handshake message (including the 16-byte Nebula header)
//   - handshakeID: the InitiatorIndex for session disambiguation
//   - noiseMsgNum: 0 for message 1 (initiator), 1 for message 2 (responder)
//   - parityShards: number of parity shards (m)
//   - chunkPayloadSize: max payload bytes per chunk
//
// The number of data shards is automatically calculated from the payload size
// and chunk payload size: k = ceil(payloadLen / chunkPayloadSize).
//
// Returns a slice of complete UDP packets (each containing Nebula header + chunk header + chunk data).
func rsEncode(msg []byte, handshakeID uint32, noiseMsgNum uint8, parityShards, chunkPayloadSize int) ([][]byte, error) {
	if len(msg) <= header.Len {
		return nil, fmt.Errorf("message too short to contain Nebula header")
	}

	// Extract the original Nebula header fields for re-encoding
	var origHeader header.H
	if err := origHeader.Parse(msg); err != nil {
		return nil, fmt.Errorf("failed to parse Nebula header: %w", err)
	}

	// The payload after the Nebula header is what we RS-encode.
	// Prepend a 4-byte length prefix so the decoder can strip RS padding.
	rawPayload := msg[header.Len:]
	payload := make([]byte, 4+len(rawPayload))
	payload[0] = byte(len(rawPayload) >> 24)
	payload[1] = byte(len(rawPayload) >> 16)
	payload[2] = byte(len(rawPayload) >> 8)
	payload[3] = byte(len(rawPayload))
	copy(payload[4:], rawPayload)

	// Auto-calculate data shards so each shard fits within chunkPayloadSize
	dataShards := (len(payload) + chunkPayloadSize - 1) / chunkPayloadSize
	if dataShards < 1 {
		dataShards = 1
	}

	totalShards := dataShards + parityShards
	if totalShards > 255 {
		return nil, fmt.Errorf("too many total shards: %d (max 255)", totalShards)
	}

	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create RS encoder: %w", err)
	}

	// Calculate shard size: divide payload into dataShards equal-sized pieces.
	shardSize := (len(payload) + dataShards - 1) / dataShards

	// Create data shards by splitting the payload
	shards := make([][]byte, totalShards)
	for i := 0; i < dataShards; i++ {
		start := i * shardSize
		end := start + shardSize
		shard := make([]byte, shardSize)
		if start < len(payload) {
			if end > len(payload) {
				end = len(payload)
			}
			copy(shard, payload[start:end])
			// Remaining bytes are already zero (padding)
		}
		shards[i] = shard
	}

	// Allocate parity shards
	for i := dataShards; i < totalShards; i++ {
		shards[i] = make([]byte, shardSize)
	}

	// Generate parity
	if err := enc.Encode(shards); err != nil {
		return nil, fmt.Errorf("RS encode failed: %w", err)
	}

	// Build complete UDP packets: Nebula header + chunk header + shard data
	packets := make([][]byte, totalShards)
	for i := 0; i < totalShards; i++ {
		pkt := make([]byte, header.Len+header.ChunkHeaderLen+len(shards[i]))

		// Encode Nebula header with chunked subtype, preserving RemoteIndex and MessageCounter
		header.Encode(pkt[:header.Len], header.Version, header.Handshake, header.HandshakeIXPSK0Chunked,
			origHeader.RemoteIndex, origHeader.MessageCounter)

		// Encode chunk header
		header.EncodeChunkHeader(pkt[header.Len:header.Len+header.ChunkHeaderLen],
			handshakeID, noiseMsgNum, uint8(i), uint8(totalShards), uint8(dataShards))

		// Copy shard data
		copy(pkt[header.Len+header.ChunkHeaderLen:], shards[i])

		packets[i] = pkt
	}

	return packets, nil
}

// rsDecode reconstructs a handshake message from RS-coded chunks.
//
// Parameters:
//   - shards: slice indexed by chunk_idx. nil entries are missing chunks.
//   - dataShards: number of data shards (k)
//   - totalShards: total number of shards (k + m)
//
// Returns the reconstructed payload (without Nebula header).
func rsDecode(shards [][]byte, dataShards, totalShards int) ([]byte, error) {
	parityShards := totalShards - dataShards
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create RS decoder: %w", err)
	}

	if err := enc.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("RS reconstruction failed: %w", err)
	}

	// Verify reconstruction
	ok, err := enc.Verify(shards)
	if err != nil {
		return nil, fmt.Errorf("RS verification failed: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("RS verification: shards are not consistent")
	}

	// Concatenate data shards to get the length-prefixed payload
	var prefixed []byte
	for i := 0; i < dataShards; i++ {
		prefixed = append(prefixed, shards[i]...)
	}

	// Extract original length from 4-byte prefix and strip RS padding
	if len(prefixed) < 4 {
		return nil, fmt.Errorf("reconstructed payload too short for length prefix")
	}
	origLen := int(prefixed[0])<<24 | int(prefixed[1])<<16 | int(prefixed[2])<<8 | int(prefixed[3])
	prefixed = prefixed[4:]
	if origLen > len(prefixed) {
		return nil, fmt.Errorf("original length %d exceeds reconstructed data %d", origLen, len(prefixed))
	}

	return prefixed[:origLen], nil
}

// needsChunking returns true if the handshake message is too large for a single UDP packet.
func needsChunking(msg []byte) bool {
	return len(msg) > header.Len+ChunkingThreshold
}

// sendHandshakeChunked RS-encodes and sends a handshake message as multiple chunks.
func sendHandshakeChunked(l *logrus.Logger, outside udp.Conn, msg []byte, handshakeID uint32, noiseMsgNum uint8, addr netip.AddrPort) error {
	chunks, err := rsEncode(msg, handshakeID, noiseMsgNum, DefaultParityShards, DefaultChunkPayloadSize)
	if err != nil {
		return fmt.Errorf("RS encode failed: %w", err)
	}

	for i, chunk := range chunks {
		if err := outside.WriteTo(chunk, addr); err != nil {
			l.WithField("chunkIdx", i).WithField("addr", addr).WithError(err).
				Error("Failed to send handshake chunk")
			// Continue sending remaining chunks - RS coding means some loss is OK
		}
	}

	return nil
}

// sendHandshakeChunkedVia RS-encodes and sends a handshake message as multiple chunks through a relay.
func sendHandshakeChunkedVia(f *Interface, via *HostInfo, relay *Relay, msg []byte, handshakeID uint32, noiseMsgNum uint8) error {
	chunks, err := rsEncode(msg, handshakeID, noiseMsgNum, DefaultParityShards, DefaultChunkPayloadSize)
	if err != nil {
		return fmt.Errorf("RS encode failed: %w", err)
	}

	for i, chunk := range chunks {
		nb := make([]byte, 12)
		out := make([]byte, mtu)
		f.SendVia(via, relay, chunk, nb, out, false)
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("chunkIdx", i).WithField("relay", via.vpnAddrs[0]).
				Debug("Sent handshake chunk via relay")
		}
	}

	return nil
}
