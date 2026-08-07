package pktgen

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Classic libpcap ("savefile") constants. We emit big-endian, so the magic
// bytes land on disk as a1 b2 c3 d4 in order; readers detect byte order from
// the magic, so tcpdump and Wireshark read our files without a hint.
const (
	pcapMagic     = 0xa1b2c3d4
	pcapMagicSwap = 0xd4c3b2a1
	linkEthernet  = 1 // LINKTYPE_ETHERNET / DLT_EN10MB
	pcapSnaplen   = 262144
	globalHdrLen  = 24
	recordHdrLen  = 16
)

// WritePcap builds each frame and writes them to w as one classic libpcap
// stream (magic 0xa1b2c3d4, LINKTYPE_ETHERNET). Timestamps are deterministic
// (seconds 0, microseconds = record index) so identical input yields a
// byte-identical file. A build error aborts the whole write.
func WritePcap(w io.Writer, frames []Frame) error {
	var hdr [globalHdrLen]byte
	binary.BigEndian.PutUint32(hdr[0:], pcapMagic)
	binary.BigEndian.PutUint16(hdr[4:], 2) // version major
	binary.BigEndian.PutUint16(hdr[6:], 4) // version minor
	// thiszone (8) + sigfigs (12) stay zero.
	binary.BigEndian.PutUint32(hdr[16:], pcapSnaplen)
	binary.BigEndian.PutUint32(hdr[20:], linkEthernet)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}

	for i, f := range frames {
		pkt, err := f.Build()
		if err != nil {
			return fmt.Errorf("pktgen: frame %d: %w", i, err)
		}
		var rec [recordHdrLen]byte
		// ts_sec stays 0; ts_usec is the record index.
		binary.BigEndian.PutUint32(rec[4:], uint32(i))
		binary.BigEndian.PutUint32(rec[8:], uint32(len(pkt)))  // incl_len
		binary.BigEndian.PutUint32(rec[12:], uint32(len(pkt))) // orig_len
		if _, err := w.Write(rec[:]); err != nil {
			return err
		}
		if _, err := w.Write(pkt); err != nil {
			return err
		}
	}
	return nil
}

// ReadPcap reads a classic libpcap stream and parses each record back into a
// Frame with Parse. It accepts both byte orders and requires
// LINKTYPE_ETHERNET. The round trip is lossless for the fields documented on
// Frame.
func ReadPcap(r io.Reader) ([]Frame, error) {
	hdr := make([]byte, globalHdrLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("pktgen: reading pcap global header: %w", err)
	}
	magic := binary.BigEndian.Uint32(hdr[0:])
	var bo binary.ByteOrder
	switch magic {
	case pcapMagic:
		bo = binary.BigEndian
	case pcapMagicSwap:
		bo = binary.LittleEndian
	default:
		return nil, fmt.Errorf("pktgen: not a libpcap file (magic %#08x)", magic)
	}
	if link := bo.Uint32(hdr[20:]); link != linkEthernet {
		return nil, fmt.Errorf("pktgen: unsupported link type %d, want %d (Ethernet)", link, linkEthernet)
	}

	var frames []Frame
	rec := make([]byte, recordHdrLen)
	for {
		_, err := io.ReadFull(r, rec)
		if err == io.EOF {
			return frames, nil
		}
		if err != nil {
			return nil, fmt.Errorf("pktgen: reading record header: %w", err)
		}
		inclLen := bo.Uint32(rec[8:])
		pkt := make([]byte, inclLen)
		if _, err := io.ReadFull(r, pkt); err != nil {
			return nil, fmt.Errorf("pktgen: reading %d-byte record: %w", inclLen, err)
		}
		f, err := Parse(pkt)
		if err != nil {
			return nil, fmt.Errorf("pktgen: parsing record %d: %w", len(frames), err)
		}
		frames = append(frames, f)
	}
}
