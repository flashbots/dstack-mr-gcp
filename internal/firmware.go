package internal

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
)

type EfiGuid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func (g EfiGuid) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		g.Data1, g.Data2, g.Data3, g.Data4[0:2], g.Data4[2:8])
}

type FwGuidEntry struct {
	Size uint16
	Guid EfiGuid
}

const fwGuidTableOffsetFromEnd = int(0x20)
const fwGuidEntrySize = 18

func convertToGuidEntry(entry []byte) (*FwGuidEntry, error) {
	if len(entry) < fwGuidEntrySize {
		return nil, fmt.Errorf("input byte slice (%d) is too small to contain an FwGuidEntry", len(entry))
	}

	var e FwGuidEntry
	reader := bytes.NewReader(entry)

	if err := binary.Read(reader, binary.LittleEndian, &e); err != nil {
		return nil, fmt.Errorf("TDX Firmware Metadata: failed to read data into struct: %w", err)
	}
	return &e, nil
}

func getLastGuidTableEntry(fw []byte) (*FwGuidEntry, error) {
	if len(fw) < fwGuidEntrySize {
		return nil, fmt.Errorf("firmware file: too few bytes to find footer: %d vs %d", len(fw), fwGuidEntrySize)
	}

	return convertToGuidEntry(fw[len(fw)-fwGuidEntrySize:])
}

func parseGuidTable(fw []byte) ([]byte, error) {
	if len(fw) < fwGuidTableOffsetFromEnd {
		return nil, fmt.Errorf("firmware file: too few bytes to find footer: %d vs %d", len(fw), fwGuidTableOffsetFromEnd)
	}
	fw = fw[:len(fw)-fwGuidTableOffsetFromEnd]

	entry, err := getLastGuidTableEntry(fw)
	if err != nil {
		return nil, err
	}

	if len(fw) < int(entry.Size) {
		return nil, fmt.Errorf("firmware file: Guid table larger than firmware: %d < %d", len(fw), entry.Size)
	}

	return fw[len(fw)-int(entry.Size) : len(fw)-fwGuidEntrySize], nil
}

func ParseGuidMap(fw []byte) (map[string][]byte, error) {
	guidTable, err := parseGuidTable(fw)
	if err != nil {
		return nil, err
	}

	guidMap := make(map[string][]byte)

	for len(guidTable) != 0 {
		entry, err := getLastGuidTableEntry(guidTable)
		if err != nil {
			return nil, err
		}

		if len(guidTable) < int(entry.Size) {
			return nil, fmt.Errorf("firmware file: table entry (%v) larger than guid table (%v)", int(entry.Size), len(guidTable))
		}

		guidMap[entry.Guid.String()] = guidTable[len(guidTable)-int(entry.Size) : len(guidTable)-fwGuidEntrySize]
		guidTable = guidTable[:len(guidTable)-int(entry.Size)]
	}

	return guidMap, nil
}

type TdxMetadataDescriptor struct {
	Signature        [4]byte
	MetadataLength   uint32
	Version          uint32
	NumberOfSections uint32
}

type TdxMetadataSection struct {
	ImageOffset   uint32
	RawDataSize   uint32
	MemoryAddress uint64
	MemorySize    uint64
	Type          uint32
	Attributes    uint32
}

const TdxMetadataOffsetGuid = "e47a6535-984a-4798-865e-4685a7bf8ec2"

func getTdxMetadataOffset(fw []byte) (int, error) {
	guidmap, err := ParseGuidMap(fw)
	if err != nil {
		return 0, err
	}
	return int(binary.LittleEndian.Uint32(guidmap[TdxMetadataOffsetGuid][:4])), nil
}

func GetTdxMetadataSections(fw []byte) ([]TdxMetadataSection, error) {
	offset, err := getTdxMetadataOffset(fw)
	if err != nil {
		return nil, err
	}
	if len(fw) < offset {
		return nil, fmt.Errorf("TDX Firmware Metadata: Metadata offset too large for firmware (likely corrupted): %v vs %v", len(fw), offset)
	}
	b := fw[len(fw)-offset:]

	var descriptor TdxMetadataDescriptor
	reader := bytes.NewReader(b)

	if err := binary.Read(reader, binary.LittleEndian, &descriptor); err != nil {
		return nil, fmt.Errorf("TDX Firmware Metadata: failed to read data into struct: %w", err)
	}

	var sections []TdxMetadataSection

	for range int(descriptor.NumberOfSections) {
		var section TdxMetadataSection
		if err := binary.Read(reader, binary.LittleEndian, &section); err != nil {
			return nil, fmt.Errorf("TDX Firmware Metadata: failed to read data into struct: %w", err)
		}
		sections = append(sections, section)
	}

	return sections, nil

}

func GetConfigurationFirmwareVolume(fw []byte) ([]byte, error) {
	sections, err := GetTdxMetadataSections(fw)
	if err != nil {
		return nil, err
	}

	var cfvSection TdxMetadataSection
	for _, section := range sections {
		// cfv is first entry of type 1
		if section.Type == 1 {
			cfvSection = section
			break
		}
	}
	base := int(cfvSection.ImageOffset)
	limit := int(cfvSection.ImageOffset + cfvSection.RawDataSize)
	if base > len(fw) {
		return nil, fmt.Errorf("TDX Firmware Metadata: CFV Section offset too large: %v vs %v", base, len(fw))
	}
	if base > len(fw) || limit < base {
		return nil, fmt.Errorf("TDX Firmware Metadata: Invalid CFV Section Size too large")
	}
	return fw[base:limit], nil
}

func GetExpectedCfvSha384(fw []byte) ([]byte, error) {
	cfvSection, err := GetConfigurationFirmwareVolume(fw)
	if err != nil {
		return nil, err
	}

	sha384 := sha512.Sum384(cfvSection)
	return sha384[:], nil
}
