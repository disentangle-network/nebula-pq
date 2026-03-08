package header

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type headerTest struct {
	expectedBytes []byte
	*H
}

// 0001 0010 00010010
var headerBigEndianTests = []headerTest{{
	expectedBytes: []byte{0x54, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9},
	// 1010 0000
	H: &H{
		// 1111 1+2+4+8 = 15
		Version:        5,
		Type:           4,
		Subtype:        0,
		Reserved:       0,
		RemoteIndex:    10,
		MessageCounter: 9,
	},
},
}

func TestEncode(t *testing.T) {
	for _, tt := range headerBigEndianTests {
		b, err := tt.Encode(make([]byte, Len))
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, tt.expectedBytes, b)
	}
}

func TestParse(t *testing.T) {
	for _, tt := range headerBigEndianTests {
		b := tt.expectedBytes
		parsedHeader := &H{}
		parsedHeader.Parse(b)

		if !reflect.DeepEqual(tt.H, parsedHeader) {
			t.Fatalf("got %#v; want %#v", parsedHeader, tt.H)
		}
	}
}

func TestTypeName(t *testing.T) {
	assert.Equal(t, "test", TypeName(Test))
	assert.Equal(t, "test", (&H{Type: Test}).TypeName())

	assert.Equal(t, "unknown", TypeName(99))
	assert.Equal(t, "unknown", (&H{Type: 99}).TypeName())
}

func TestSubTypeName(t *testing.T) {
	assert.Equal(t, "testRequest", SubTypeName(Test, TestRequest))
	assert.Equal(t, "testRequest", (&H{Type: Test, Subtype: TestRequest}).SubTypeName())

	assert.Equal(t, "unknown", SubTypeName(99, TestRequest))
	assert.Equal(t, "unknown", (&H{Type: 99, Subtype: TestRequest}).SubTypeName())

	assert.Equal(t, "unknown", SubTypeName(Test, 99))
	assert.Equal(t, "unknown", (&H{Type: Test, Subtype: 99}).SubTypeName())

	assert.Equal(t, "none", SubTypeName(Message, 0))
	assert.Equal(t, "none", (&H{Type: Message, Subtype: 0}).SubTypeName())
}

func TestTypeMap(t *testing.T) {
	// Force people to document this stuff
	assert.Equal(t, map[MessageType]string{
		Handshake:   "handshake",
		Message:     "message",
		RecvError:   "recvError",
		LightHouse:  "lightHouse",
		Test:        "test",
		CloseTunnel: "closeTunnel",
		Control:     "control",
	}, typeMap)

	assert.Equal(t, map[MessageType]*map[MessageSubType]string{
		Message: {
			MessageNone:  "none",
			MessageRelay: "relay",
		},
		RecvError:   &subTypeNoneMap,
		LightHouse:  &subTypeNoneMap,
		Test:        &subTypeTestMap,
		CloseTunnel: &subTypeNoneMap,
		Handshake: {
			HandshakeIXPSK0:        "ix_psk0",
			HandshakeIXPSK0Chunked: "ix_psk0_chunked",
		},
		Control: &subTypeNoneMap,
	}, subTypeMap)
}

func TestHeader_String(t *testing.T) {
	assert.Equal(
		t,
		"ver=100 type=test subtype=testRequest reserved=0x63 remoteindex=98 messagecounter=97",
		(&H{100, Test, TestRequest, 99, 98, 97}).String(),
	)
}

func TestHeader_MarshalJSON(t *testing.T) {
	b, err := (&H{100, Test, TestRequest, 99, 98, 97}).MarshalJSON()
	require.NoError(t, err)
	assert.Equal(
		t,
		"{\"messageCounter\":97,\"remoteIndex\":98,\"reserved\":99,\"subType\":\"testRequest\",\"type\":\"test\",\"version\":100}",
		string(b),
	)
}

func TestChunkHeaderEncodeParse(t *testing.T) {
	original := &ChunkHeader{
		HandshakeID: 0xDEADBEEF,
		NoiseMsgNum: 0,
		ChunkIdx:    3,
		TotalChunks: 8,
		DataShards:  5,
	}

	b := make([]byte, ChunkHeaderLen)
	encoded, err := original.Encode(b)
	require.NoError(t, err)
	assert.Len(t, encoded, ChunkHeaderLen)

	parsed := &ChunkHeader{}
	err = parsed.Parse(encoded)
	require.NoError(t, err)
	assert.Equal(t, original, parsed)
}

func TestEncodeChunkHeader(t *testing.T) {
	b := EncodeChunkHeader(make([]byte, ChunkHeaderLen), 42, 1, 2, 8, 5)
	assert.Len(t, b, ChunkHeaderLen)

	ch := &ChunkHeader{}
	err := ch.Parse(b)
	require.NoError(t, err)
	assert.Equal(t, uint32(42), ch.HandshakeID)
	assert.Equal(t, uint8(1), ch.NoiseMsgNum)
	assert.Equal(t, uint8(2), ch.ChunkIdx)
	assert.Equal(t, uint8(8), ch.TotalChunks)
	assert.Equal(t, uint8(5), ch.DataShards)
}

func TestChunkHeader_ParseTooShort(t *testing.T) {
	ch := &ChunkHeader{}
	err := ch.Parse([]byte{1, 2, 3})
	assert.Equal(t, ErrChunkHeaderTooShort, err)
}

func TestChunkHeader_EncodeNil(t *testing.T) {
	var ch *ChunkHeader
	_, err := ch.Encode(make([]byte, ChunkHeaderLen))
	assert.Error(t, err)
}

func TestChunkHeader_String(t *testing.T) {
	ch := &ChunkHeader{
		HandshakeID: 100,
		NoiseMsgNum: 0,
		ChunkIdx:    2,
		TotalChunks: 8,
		DataShards:  5,
	}
	s := ch.String()
	assert.Equal(t, "handshake_id=100 noise_msg=0 chunk=2/8 data_shards=5", s)

	var nilCh *ChunkHeader
	assert.Equal(t, "<nil>", nilCh.String())
}

func TestHandshakeIXPSK0Chunked_SubTypeName(t *testing.T) {
	assert.Equal(t, "ix_psk0_chunked", SubTypeName(Handshake, HandshakeIXPSK0Chunked))
	assert.Equal(t, "ix_psk0_chunked", (&H{Type: Handshake, Subtype: HandshakeIXPSK0Chunked}).SubTypeName())
}
