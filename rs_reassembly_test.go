package nebula

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestReassemblyManager() *ReassemblyManager {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return NewReassemblyManager(l)
}

func makeTestHandshakeMsg(payloadSize int, remoteIndex uint32, msgCounter uint64) []byte {
	msg := make([]byte, header.Len+payloadSize)
	header.Encode(msg[:header.Len], header.Version, header.Handshake, header.HandshakeIXPSK0, remoteIndex, msgCounter)
	rand.Read(msg[header.Len:])
	return msg
}

func TestReassemblyManagerBasicReassembly(t *testing.T) {
	rm := newTestReassemblyManager()

	payloadSize := 9000
	msg := makeTestHandshakeMsg(payloadSize, 42, 1)
	handshakeID := uint32(42)
	noiseMsgNum := uint8(0)

	chunks, err := rsEncode(msg, handshakeID, noiseMsgNum, DefaultParityShards, DefaultChunkPayloadSize)
	require.NoError(t, err)

	// Feed all chunks; only the last one should trigger reassembly
	var result []byte
	var ok bool
	for _, chunk := range chunks {
		var h header.H
		require.NoError(t, h.Parse(chunk))
		result, ok = rm.HandleChunk(chunk, &h)
		if ok {
			break
		}
	}

	require.True(t, ok, "reassembly should have completed")
	require.NotNil(t, result)

	// Verify the reassembled message has a proper Nebula header
	var rh header.H
	require.NoError(t, rh.Parse(result))
	assert.Equal(t, header.Handshake, rh.Type)
	assert.Equal(t, header.HandshakeIXPSK0, rh.Subtype)
	assert.Equal(t, uint64(1), rh.MessageCounter)

	// Verify payload matches
	assert.Equal(t, msg[header.Len:], result[header.Len:header.Len+payloadSize])
}

func TestReassemblyManagerWithMissingShards(t *testing.T) {
	rm := newTestReassemblyManager()

	payloadSize := 9000
	msg := makeTestHandshakeMsg(payloadSize, 77, 1)

	chunks, err := rsEncode(msg, 77, 0, DefaultParityShards, DefaultChunkPayloadSize)
	require.NoError(t, err)

	// Drop the first DefaultParityShards chunks (simulate packet loss)
	var result []byte
	var ok bool
	for i, chunk := range chunks {
		if i < DefaultParityShards {
			continue // Drop these chunks
		}
		var h header.H
		require.NoError(t, h.Parse(chunk))
		result, ok = rm.HandleChunk(chunk, &h)
		if ok {
			break
		}
	}

	require.True(t, ok, "reassembly should succeed with %d missing shards", DefaultParityShards)
	require.NotNil(t, result)
	assert.Equal(t, msg[header.Len:], result[header.Len:header.Len+payloadSize])
}

func TestReassemblyManagerDuplicateChunks(t *testing.T) {
	rm := newTestReassemblyManager()

	payloadSize := 9000
	msg := makeTestHandshakeMsg(payloadSize, 88, 1)

	chunks, err := rsEncode(msg, 88, 0, DefaultParityShards, DefaultChunkPayloadSize)
	require.NoError(t, err)

	// Send every chunk twice
	var result []byte
	var ok bool
	for _, chunk := range chunks {
		var h header.H
		require.NoError(t, h.Parse(chunk))
		// First time
		result, ok = rm.HandleChunk(chunk, &h)
		if ok {
			break
		}
		// Duplicate
		result, ok = rm.HandleChunk(chunk, &h)
		if ok {
			break
		}
	}

	require.True(t, ok)
	require.NotNil(t, result)
	assert.Equal(t, msg[header.Len:], result[header.Len:header.Len+payloadSize])
}

func TestReassemblyManagerMultipleSessions(t *testing.T) {
	rm := newTestReassemblyManager()

	// Create two different handshake sessions
	msg1 := makeTestHandshakeMsg(9000, 11, 1)
	msg2 := makeTestHandshakeMsg(9000, 22, 1)

	chunks1, err := rsEncode(msg1, 11, 0, DefaultParityShards, DefaultChunkPayloadSize)
	require.NoError(t, err)
	chunks2, err := rsEncode(msg2, 22, 0, DefaultParityShards, DefaultChunkPayloadSize)
	require.NoError(t, err)

	// Interleave chunks from both sessions
	var result1, result2 []byte
	maxChunks := len(chunks1)
	if len(chunks2) > maxChunks {
		maxChunks = len(chunks2)
	}

	for i := 0; i < maxChunks; i++ {
		if i < len(chunks1) && result1 == nil {
			var h header.H
			require.NoError(t, h.Parse(chunks1[i]))
			r, ok := rm.HandleChunk(chunks1[i], &h)
			if ok {
				result1 = r
			}
		}
		if i < len(chunks2) && result2 == nil {
			var h header.H
			require.NoError(t, h.Parse(chunks2[i]))
			r, ok := rm.HandleChunk(chunks2[i], &h)
			if ok {
				result2 = r
			}
		}
	}

	require.NotNil(t, result1, "session 1 should reassemble")
	require.NotNil(t, result2, "session 2 should reassemble")
	assert.Equal(t, msg1[header.Len:], result1[header.Len:header.Len+9000])
	assert.Equal(t, msg2[header.Len:], result2[header.Len:header.Len+9000])
}

func TestReassemblyManagerExpiry(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	rm := NewReassemblyManager(l)

	payloadSize := 9000
	msg := makeTestHandshakeMsg(payloadSize, 99, 1)

	chunks, err := rsEncode(msg, 99, 0, DefaultParityShards, DefaultChunkPayloadSize)
	require.NoError(t, err)

	// Feed only one chunk
	var h header.H
	require.NoError(t, h.Parse(chunks[0]))
	_, ok := rm.HandleChunk(chunks[0], &h)
	assert.False(t, ok)

	// Verify buffer exists
	rm.mu.Lock()
	assert.Len(t, rm.buffers, 1)
	// Artificially age the buffer
	for k := range rm.buffers {
		rm.buffers[k].created = time.Now().Add(-ReassemblyTimeout - time.Second)
	}
	rm.mu.Unlock()

	// Expire should clean it up
	rm.ExpireBuffers()

	rm.mu.Lock()
	assert.Len(t, rm.buffers, 0)
	rm.mu.Unlock()
}

func TestReassemblyManagerBufferLimit(t *testing.T) {
	rm := newTestReassemblyManager()

	// Fill up to the limit
	for i := 0; i < MaxReassemblyBuffers; i++ {
		msg := makeTestHandshakeMsg(2000, uint32(i+1), 1)
		chunks, err := rsEncode(msg, uint32(i+1), 0, DefaultParityShards, DefaultChunkPayloadSize)
		require.NoError(t, err)

		// Only send one chunk each (so buffer stays open)
		var h header.H
		require.NoError(t, h.Parse(chunks[0]))
		rm.HandleChunk(chunks[0], &h)
	}

	rm.mu.Lock()
	assert.Len(t, rm.buffers, MaxReassemblyBuffers)
	rm.mu.Unlock()

	// Next chunk for a new session should be rejected
	msg := makeTestHandshakeMsg(2000, 9999, 1)
	chunks, err := rsEncode(msg, 9999, 0, DefaultParityShards, DefaultChunkPayloadSize)
	require.NoError(t, err)
	var h header.H
	require.NoError(t, h.Parse(chunks[0]))
	_, ok := rm.HandleChunk(chunks[0], &h)
	assert.False(t, ok)

	// Verify the 9999 buffer was not created
	rm.mu.Lock()
	_, exists := rm.buffers[reassemblyKey{handshakeID: 9999, noiseMsgNum: 0}]
	rm.mu.Unlock()
	assert.False(t, exists)
}

func TestReassemblyManagerTooShortPacket(t *testing.T) {
	rm := newTestReassemblyManager()
	h := &header.H{Type: header.Handshake, Subtype: header.HandshakeIXPSK0Chunked}
	_, ok := rm.HandleChunk([]byte{1, 2, 3}, h)
	assert.False(t, ok)
}

func TestReassemblyManagerMessage2(t *testing.T) {
	rm := newTestReassemblyManager()

	payloadSize := 9200
	msg := makeTestHandshakeMsg(payloadSize, 55, 2)

	chunks, err := rsEncode(msg, 55, 1, DefaultParityShards, DefaultChunkPayloadSize)
	require.NoError(t, err)

	var result []byte
	var ok bool
	for _, chunk := range chunks {
		var h header.H
		require.NoError(t, h.Parse(chunk))
		result, ok = rm.HandleChunk(chunk, &h)
		if ok {
			break
		}
	}

	require.True(t, ok)
	require.NotNil(t, result)

	// Verify reconstructed header has msgCounter=2 for noise message 2
	var rh header.H
	require.NoError(t, rh.Parse(result))
	assert.Equal(t, uint64(2), rh.MessageCounter)
	assert.Equal(t, msg[header.Len:], result[header.Len:header.Len+payloadSize])
}
