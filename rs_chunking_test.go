package nebula

import (
	"crypto/rand"
	"testing"

	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRsEncodeDecodeRoundTrip(t *testing.T) {
	// Simulate a ~9KB PQ handshake message (Nebula header + payload)
	payloadSize := 9000
	msg := make([]byte, header.Len+payloadSize)

	// Encode a valid Nebula header
	header.Encode(msg[:header.Len], header.Version, header.Handshake, header.HandshakeIXPSK0, 42, 1)

	// Fill payload with random data
	_, err := rand.Read(msg[header.Len:])
	require.NoError(t, err)

	handshakeID := uint32(42)
	noiseMsgNum := uint8(0)

	// Encode
	chunks, err := rsEncode(msg, handshakeID, noiseMsgNum, DefaultParityShards, DefaultChunkPayloadSize)
	require.NoError(t, err)

	// rsEncode prepends a 4-byte length prefix, so effective payload is payloadSize + 4
	expectedDataShards := (payloadSize + 4 + DefaultChunkPayloadSize - 1) / DefaultChunkPayloadSize
	expectedTotal := expectedDataShards + DefaultParityShards
	assert.Len(t, chunks, expectedTotal)

	// Verify each chunk has correct headers
	for i, chunk := range chunks {
		assert.True(t, len(chunk) <= header.Len+header.ChunkHeaderLen+DefaultChunkPayloadSize,
			"chunk %d too large: %d bytes", i, len(chunk))

		var h header.H
		require.NoError(t, h.Parse(chunk))
		assert.Equal(t, header.Version, h.Version)
		assert.Equal(t, header.Handshake, h.Type)
		assert.Equal(t, header.HandshakeIXPSK0Chunked, h.Subtype)
		assert.Equal(t, uint32(42), h.RemoteIndex)
		assert.Equal(t, uint64(1), h.MessageCounter)

		var ch header.ChunkHeader
		require.NoError(t, ch.Parse(chunk[header.Len:]))
		assert.Equal(t, handshakeID, ch.HandshakeID)
		assert.Equal(t, noiseMsgNum, ch.NoiseMsgNum)
		assert.Equal(t, uint8(i), ch.ChunkIdx)
		assert.Equal(t, uint8(expectedTotal), ch.TotalChunks)
		assert.Equal(t, uint8(expectedDataShards), ch.DataShards)
	}

	// Extract shards for decoding
	shards := extractShards(chunks)

	// Decode with all shards present
	payload, err := rsDecode(shards, expectedDataShards, expectedTotal)
	require.NoError(t, err)

	// The reconstructed payload should exactly match the original (length prefix strips padding)
	originalPayload := msg[header.Len:]
	assert.Equal(t, originalPayload, payload)
}

func TestRsDecodeWithMissingShards(t *testing.T) {
	payloadSize := 9000
	msg := make([]byte, header.Len+payloadSize)
	header.Encode(msg[:header.Len], header.Version, header.Handshake, header.HandshakeIXPSK0, 100, 1)
	_, err := rand.Read(msg[header.Len:])
	require.NoError(t, err)

	chunks, err := rsEncode(msg, 100, 0, DefaultParityShards, DefaultChunkPayloadSize)
	require.NoError(t, err)

	dataShards := (payloadSize + 4 + DefaultChunkPayloadSize - 1) / DefaultChunkPayloadSize
	totalShards := dataShards + DefaultParityShards

	allShards := extractShards(chunks)

	// Test with up to DefaultParityShards missing (should succeed)
	for numMissing := 1; numMissing <= DefaultParityShards; numMissing++ {
		shards := make([][]byte, totalShards)
		for i := range shards {
			if i < numMissing {
				shards[i] = nil // Missing shard
			} else {
				shards[i] = make([]byte, len(allShards[i]))
				copy(shards[i], allShards[i])
			}
		}

		payload, err := rsDecode(shards, dataShards, totalShards)
		require.NoError(t, err, "failed with %d missing shards", numMissing)

		originalPayload := msg[header.Len:]
		assert.Equal(t, originalPayload, payload,
			"payload mismatch with %d missing shards", numMissing)
	}
}

func TestRsDecodeTooManyMissing(t *testing.T) {
	payloadSize := 9000
	msg := make([]byte, header.Len+payloadSize)
	header.Encode(msg[:header.Len], header.Version, header.Handshake, header.HandshakeIXPSK0, 100, 1)
	_, err := rand.Read(msg[header.Len:])
	require.NoError(t, err)

	chunks, err := rsEncode(msg, 100, 0, DefaultParityShards, DefaultChunkPayloadSize)
	require.NoError(t, err)

	dataShards := (payloadSize + 4 + DefaultChunkPayloadSize - 1) / DefaultChunkPayloadSize
	totalShards := dataShards + DefaultParityShards

	shards := extractShards(chunks)

	// Remove DefaultParityShards + 1 shards (too many)
	for i := 0; i <= DefaultParityShards; i++ {
		shards[i] = nil
	}

	_, err = rsDecode(shards, dataShards, totalShards)
	assert.Error(t, err)
}

func TestNeedsChunking(t *testing.T) {
	// Small message: no chunking needed
	small := make([]byte, header.Len+500)
	assert.False(t, needsChunking(small))

	// Exactly at threshold: no chunking needed
	threshold := make([]byte, header.Len+ChunkingThreshold)
	assert.False(t, needsChunking(threshold))

	// Over threshold: chunking needed
	large := make([]byte, header.Len+ChunkingThreshold+1)
	assert.True(t, needsChunking(large))
}

func TestRsEncodeSmallMessage(t *testing.T) {
	// A message too short (no Nebula header) should fail
	_, err := rsEncode([]byte{1, 2, 3}, 1, 0, DefaultParityShards, DefaultChunkPayloadSize)
	assert.Error(t, err)
}

func TestRsEncodeDecodeMessage2(t *testing.T) {
	// Test with noiseMsgNum = 1 (responder message)
	payloadSize := 9200
	msg := make([]byte, header.Len+payloadSize)
	header.Encode(msg[:header.Len], header.Version, header.Handshake, header.HandshakeIXPSK0, 55, 2)
	_, err := rand.Read(msg[header.Len:])
	require.NoError(t, err)

	chunks, err := rsEncode(msg, 55, 1, DefaultParityShards, DefaultChunkPayloadSize)
	require.NoError(t, err)

	// Verify chunk headers have correct noiseMsgNum
	for _, chunk := range chunks {
		var ch header.ChunkHeader
		require.NoError(t, ch.Parse(chunk[header.Len:]))
		assert.Equal(t, uint8(1), ch.NoiseMsgNum)
		assert.Equal(t, uint32(55), ch.HandshakeID)
	}

	// Decode
	dataShards := (payloadSize + 4 + DefaultChunkPayloadSize - 1) / DefaultChunkPayloadSize
	totalShards := dataShards + DefaultParityShards

	shards := extractShards(chunks)
	payload, err := rsDecode(shards, dataShards, totalShards)
	require.NoError(t, err)

	originalPayload := msg[header.Len:]
	assert.Equal(t, originalPayload, payload)
}

func TestRsEncodeDecodeVariousSizes(t *testing.T) {
	// Test with various payload sizes to ensure dynamic data shard calculation works
	sizes := []int{1201, 2400, 4800, 6000, 9000, 9129}

	for _, payloadSize := range sizes {
		msg := make([]byte, header.Len+payloadSize)
		header.Encode(msg[:header.Len], header.Version, header.Handshake, header.HandshakeIXPSK0, 1, 1)
		_, err := rand.Read(msg[header.Len:])
		require.NoError(t, err)

		chunks, err := rsEncode(msg, 1, 0, DefaultParityShards, DefaultChunkPayloadSize)
		require.NoError(t, err, "encode failed for payload size %d", payloadSize)

		expectedDataShards := (payloadSize + 4 + DefaultChunkPayloadSize - 1) / DefaultChunkPayloadSize
		expectedTotal := expectedDataShards + DefaultParityShards
		assert.Len(t, chunks, expectedTotal, "wrong chunk count for payload size %d", payloadSize)

		// Verify round trip
		shards := extractShards(chunks)
		payload, err := rsDecode(shards, expectedDataShards, expectedTotal)
		require.NoError(t, err, "decode failed for payload size %d", payloadSize)
		assert.Equal(t, msg[header.Len:], payload, "payload mismatch for size %d", payloadSize)
	}
}

// extractShards extracts the shard data from encoded chunks (strips Nebula header + chunk header).
func extractShards(chunks [][]byte) [][]byte {
	shards := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		shards[i] = make([]byte, len(chunk)-header.Len-header.ChunkHeaderLen)
		copy(shards[i], chunk[header.Len+header.ChunkHeaderLen:])
	}
	return shards
}
