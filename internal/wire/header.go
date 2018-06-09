package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// Header is the header of a QUIC packet.
// It contains fields that are only needed for the gQUIC Public Header and the IETF draft Header.
type Header struct {
	IsPublicHeader bool

	Raw []byte

	Version protocol.VersionNumber

	DestConnectionID protocol.ConnectionID
	SrcConnectionID  protocol.ConnectionID
	OmitConnectionID bool

	IsVersionNegotiation bool
	SupportedVersions    []protocol.VersionNumber // Version Number sent in a Version Negotiation Packet by the server

	// only needed for the gQUIC Public Header
	VersionFlag          bool
	ResetFlag            bool
	DiversificationNonce []byte

	// only needed for the IETF Header
	Type         protocol.PacketType
	IsLongHeader bool
	KeyPhase     int
	Length       protocol.ByteCount
}

// ParseHeaderSentByServer parses the header for a packet that was sent by the server.
func ParseHeaderSentByServer(b *bytes.Reader) (*Header, error) {
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	_ = b.UnreadByte() // unread the type byte

	var isPublicHeader bool
	if typeByte&0x80 > 0 { // gQUIC always has 0x80 unset. IETF Long Header or Version Negotiation
		isPublicHeader = false
	} else {
		// gQUIC never uses 6 byte packet numbers, so the third and fourth bit will never be 11
		isPublicHeader = typeByte&0x30 != 0x30
	}
	return parsePacketHeader(b, protocol.PerspectiveServer, isPublicHeader)
}

// ParseHeaderSentByClient parses the header for a packet that was sent by the client.
func ParseHeaderSentByClient(b *bytes.Reader) (*Header, error) {
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	_ = b.UnreadByte() // unread the type byte

	// In an IETF QUIC packet header
	// * either 0x80 is set (for the Long Header)
	// * or 0x8 is unset (for the Short Header)
	// In a gQUIC Public Header
	// * 0x80 is always unset and
	// * and 0x8 is always set (this is the Connection ID flag, which the client always sets)
	isPublicHeader := typeByte&0x88 == 0x8
	return parsePacketHeader(b, protocol.PerspectiveClient, isPublicHeader)
}

func parsePacketHeader(b *bytes.Reader, sentBy protocol.Perspective, isPublicHeader bool) (*Header, error) {
	// This is a gQUIC Public Header.
	if isPublicHeader {
		hdr, err := parsePublicHeader(b, sentBy)
		if err != nil {
			return nil, err
		}
		hdr.IsPublicHeader = true // save that this is a Public Header, so we can log it correctly later
		return hdr, nil
	}
	return parseHeader(b)
}

// ReadPacketNumber reads the packet number.
// Since the packet number follows the header, it should be called after parsing the header.
func ReadPacketNumber(b *bytes.Reader, flagByte byte, version protocol.VersionNumber) (protocol.PacketNumber, protocol.PacketNumberLen, error) {
	if !version.UsesTLS() {
		return readPublicHeaderPacketNumber(b, flagByte)
	}
	return readPacketNumber(b, flagByte)
}

// Write writes the Header.
func (h *Header) Write(
	b *bytes.Buffer,
	pn protocol.PacketNumber,
	pnLen protocol.PacketNumberLen,
	pers protocol.Perspective,
	version protocol.VersionNumber,
) error {
	if !version.UsesTLS() {
		h.IsPublicHeader = true // save that this is a Public Header, so we can log it correctly later
		return h.writePublicHeader(b, pn, pnLen, pers)
	}
	return h.writeHeader(b, pn, pnLen)
}

// GetLength determines the length of the Header.
func (h *Header) GetLength(pnLen protocol.PacketNumberLen, pers protocol.Perspective, version protocol.VersionNumber) (protocol.ByteCount, error) {
	if !version.UsesTLS() {
		return h.getPublicHeaderLength(pnLen, pers)
	}
	return h.getHeaderLength(pnLen), nil
}

// Log logs the Header
func (h *Header) Log(logger utils.Logger) {
	if h.IsPublicHeader {
		h.logPublicHeader(logger)
	} else {
		h.logHeader(logger)
	}
}
