package internal

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"hash/crc32"
)

// Disk size constants
const (
	diskSizeBytes   = 1024 * 1024 * 1024 // 1GB
	diskSizeSectors = diskSizeBytes / 512
	partitionName   = "ESP"
)

// LBA (Logical Block Address) constants
const (
	gptHeaderLBA      = 1
	partitionEntryLBA = 2
	espStartingLBA    = 2048
	espEndingLBA      = 1026047
)

// GUID constants for disk and partition
const (
	diskGUID         = "12345678-1234-5678-1234-567812345678"
	espPartitionGUID = "87654321-4321-8765-4321-876543218765"
)

// Generates the deterministic UEFI disk GUID hash for TDX measurements
func calculateUEFIDiskGUIDHash() []byte {
	// GPT Header at LBA 1
	header := struct {
		Signature                [8]byte
		Revision                 uint32
		HeaderSize               uint32
		HeaderCRC32              uint32
		Reserved                 uint32
		MyLBA                    uint64
		AlternateLBA             uint64
		FirstUsableLBA           uint64
		LastUsableLBA            uint64
		DiskGUID                 [16]byte
		PartitionEntryLBA        uint64
		NumberOfPartitionEntries uint32
		SizeOfPartitionEntry     uint32
		PartitionEntryArrayCRC32 uint32
	}{
		Signature:                [8]byte{'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'},
		Revision:                 0x00010000,
		HeaderSize:               92,
		Reserved:                 0,
		MyLBA:                    gptHeaderLBA,
		AlternateLBA:             diskSizeSectors - 1,
		FirstUsableLBA:           34,
		LastUsableLBA:            diskSizeSectors - 34,
		PartitionEntryLBA:        partitionEntryLBA,
		NumberOfPartitionEntries: 128,
		SizeOfPartitionEntry:     128,
	}
	copy(header.DiskGUID[:], encodeGUID(diskGUID))

	// ESP Partition Entry
	partition := struct {
		PartitionTypeGUID   [16]byte
		UniquePartitionGUID [16]byte
		StartingLBA         uint64
		EndingLBA           uint64
		Attributes          uint64
		PartitionName       [72]byte
	}{
		StartingLBA: espStartingLBA,
		EndingLBA:   espEndingLBA,
		Attributes:  0x0000000000000001, // Bit 0 = Platform required
	}
	copy(partition.PartitionTypeGUID[:], encodeGUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")) // EFI System Partition
	copy(partition.UniquePartitionGUID[:], encodeGUID(espPartitionGUID))

	// Set partition name "ESP" in UTF-16LE
	for i, r := range partitionName {
		binary.LittleEndian.PutUint16(partition.PartitionName[i*2:], uint16(r))
	}

	// Calculate CRCs
	partitionBytes := new(bytes.Buffer)
	binary.Write(partitionBytes, binary.LittleEndian, partition)

	// Create full partition array (128 entries * 128 bytes)
	partitionArray := make([]byte, 128*128)
	copy(partitionArray, partitionBytes.Bytes())
	header.PartitionEntryArrayCRC32 = crc32.ChecksumIEEE(partitionArray)

	// Calculate header CRC
	headerBuf := new(bytes.Buffer)
	binary.Write(headerBuf, binary.LittleEndian, header)
	headerBytes := headerBuf.Bytes()
	header.HeaderCRC32 = crc32.ChecksumIEEE(headerBytes[:92])

	// Build UEFI_GPT_DATA structure for measurement
	var measurementBuf bytes.Buffer
	binary.Write(&measurementBuf, binary.LittleEndian, header)
	binary.Write(&measurementBuf, binary.LittleEndian, uint64(1)) // Number of actual partitions
	binary.Write(&measurementBuf, binary.LittleEndian, partition)

	// Calculate SHA384
	hash := sha512.Sum384(measurementBuf.Bytes())
	return hash[:]
}
