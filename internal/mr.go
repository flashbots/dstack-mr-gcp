package internal

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/foxboron/go-uefi/authenticode"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// measureSha384 computes a SHA384 of the given blob.
func measureSha384(data []byte) []byte {
	h := sha512.Sum384(data)
	return h[:]
}

// measureTdxKernelCmdline measures the kernel cmdline.
func measureTdxKernelCmdline(cmdline string) []byte {
	// Add a NUL byte at the end.
	d := append([]byte(cmdline), 0x00)
	// Convert to UTF-16LE.
	utf16le := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	xr := transform.NewReader(bytes.NewReader(d), utf16le)
	converted, _ := io.ReadAll(xr)
	return measureSha384(converted)
}

// measureTdxQemuTdHob measures the TD HOB.
func measureTdxQemuTdHob(memorySize uint64 /*, meta *tdvfMetadata*/) []byte {
	// Construct a TD hob in the same way as QEMU does. Note that all fields are little-endian.
	// See: https://github.com/intel-staging/qemu-tdx/blob/tdx-qemu-next/hw/i386/tdvf-hob.c
	var tdHob []byte
	// Discover the TD HOB base address from TDVF metadata.
	tdHobBaseAddr := uint64(0x809000) // TD HOB base address.
	/*if meta != nil {
		for _, s := range meta.sections {
			if s.secType == tdvfSectionTdHob {
				tdHobBaseAddr = s.memoryAddress
				break
			}
		}
	}*/

	// Start with EFI_HOB_TYPE_HANDOFF.
	tdHob = append(tdHob,
		0x01, 0x00, // Header.HobType (EFI_HOB_TYPE_HANDOFF)
		0x38, 0x00, // Header.HobLength (56 bytes)
		0x00, 0x00, 0x00, 0x00, // Header.Reserved
		0x09, 0x00, 0x00, 0x00, // Version (EFI_HOB_HANDOFF_TABLE_VERSION)
		0x00, 0x00, 0x00, 0x00, // BootMode
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EfiMemoryTop
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EfiMemoryBottom
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EfiFreeMemoryTop
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EfiFreeMemoryBottom
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EfiEndOfHobList (filled later)
	)

	// The rest of the HOBs are EFI_HOB_TYPE_RESOURCE_DESCRIPTOR.
	remainingMemory := memorySize
	addMemoryResourceHob := func(resourceType uint8, start, length uint64) {
		tdHob = append(tdHob,
			0x03, 0x00, // Header.HobType (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR)
			0x30, 0x00, // Header.HobLength (48 bytes)
			0x00, 0x00, 0x00, 0x00, // Header.Reserved
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Owner
			resourceType, 0x00, 0x00, 0x00, // ResourceType
			0x07, 0x00, 0x00, 0x00, // ResourceAttribute
		)

		var val [8]byte
		binary.LittleEndian.PutUint64(val[:], start)
		tdHob = append(tdHob, val[:]...) // PhysicalStart
		binary.LittleEndian.PutUint64(val[:], length)
		tdHob = append(tdHob, val[:]...) // Length

		// Subtract from remaining memory.
		remainingMemory -= length
	}

	addMemoryResourceHob(0x07, 0x0000000000000000, 0x0000000000800000)
	addMemoryResourceHob(0x00, 0x0000000000800000, 0x0000000000006000)
	addMemoryResourceHob(0x07, 0x0000000000806000, 0x0000000000003000)
	addMemoryResourceHob(0x00, 0x0000000000809000, 0x0000000000002000)
	addMemoryResourceHob(0x00, 0x000000000080B000, 0x0000000000002000)
	addMemoryResourceHob(0x07, 0x000000000080D000, 0x0000000000004000)
	addMemoryResourceHob(0x00, 0x0000000000811000, 0x000000000000f000)

	// Handle memory split at 2816 MiB (0xB0000000).
	if memorySize >= 0xB0000000 {
		addMemoryResourceHob(0x07, 0x0000000000820000, 0x000000007F7E0000)
		addMemoryResourceHob(0x07, 0x0000000100000000, remainingMemory)
	} else {
		addMemoryResourceHob(0x07, 0x0000000000820000, remainingMemory)
	}

	// Update EfiEndOfHobList.
	var val [8]byte
	binary.LittleEndian.PutUint64(val[:], tdHobBaseAddr+uint64(len(tdHob))+8)
	copy(tdHob[48:56], val[:])

	// Measure the TD HOB.
	return measureSha384(tdHob)
}

// measureLog computes a measurement of the given RTMR event log by simulating extending the RTMR.
func measureLog(log [][]byte, debug bool, rtmrName string) []byte {
	if debug && rtmrName != "" {
		fmt.Printf("\n=== %s Event Hashes ===\n", rtmrName)
	}
	var mr [48]byte // Initialize to zero.
	for i, entry := range log {
		if debug && rtmrName != "" {
			fmt.Printf("%s[%d]: %x\n", rtmrName, i, entry)
		}
		h := sha512.New384()
		_, _ = h.Write(mr[:])
		_, _ = h.Write(entry)
		copy(mr[:], h.Sum([]byte{}))
	}
	return mr[:]
}

// encodeGUID encodes an UEFI GUID into binary form.
func encodeGUID(guid string) []byte {
	var data []byte
	atoms := strings.Split(guid, "-")
	for idx, atom := range atoms {
		raw, err := hex.DecodeString(atom)
		if err != nil {
			panic("bad GUID")
		}

		if idx <= 2 {
			// Little-endian.
			for i := range raw {
				data = append(data, raw[len(raw)-1-i])
			}
		} else {
			// Big-endian.
			data = append(data, raw...)
		}
	}
	return data
}

// extractKernelPE extracts the .linux section from a UKI
func extractKernel(ukiData []byte) []byte {
	f, err := pe.NewFile(bytes.NewReader(ukiData))
	if err != nil {
		panic("failed to parse UKI as PE file")
	}
	defer f.Close()
	data, err := f.Section(".linux").Data()
	if err != nil {
		panic("failed to extract .linux section from UKI")
	}
	return data
}

// measureTdxEfiVariable measures an EFI variable event.
func measureTdxEfiVariable(vendorGUID string, varName string) []byte {
	var data []byte
	data = append(data, encodeGUID(vendorGUID)...)

	var encLen [8]byte
	binary.LittleEndian.PutUint64(encLen[:], uint64(len(varName)))
	data = append(data, encLen[:]...)
	binary.LittleEndian.PutUint64(encLen[:], 0)
	data = append(data, encLen[:]...)

	// Convert varName to UTF-16LE.
	utf16le := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	xr := transform.NewReader(bytes.NewReader([]byte(varName)), utf16le)
	converted, _ := io.ReadAll(xr)
	data = append(data, converted...)

	return measureSha384(data)
}

// TdxMeasurements contains all the measurement values for TDX
type TdxMeasurements struct {
	MRTD  []byte
	RTMR0 []byte
	RTMR1 []byte
	RTMR2 []byte
}

// CalculateMrAggregated calculates mr_aggregated = sha256(mrtd+rtmr0+rtmr1+rtmr2+mr_key_provider)
func (m *TdxMeasurements) CalculateMrAggregated(mrKeyProvider string) string {
	// Strip "0x" prefix if present
	mrKeyProvider = strings.TrimPrefix(mrKeyProvider, "0x")
	mrKeyProviderBytes, err := hex.DecodeString(mrKeyProvider)
	if err != nil {
		panic("invalid mr_key_provider")
	}
	h := sha256.New()
	h.Write(m.MRTD)
	h.Write(m.RTMR0)
	h.Write(m.RTMR1)
	h.Write(m.RTMR2)
	h.Write(mrKeyProviderBytes)
	return hex.EncodeToString(h.Sum(nil))
}

// CalculateMrImage calculates mr_image = sha256(mrtd+rtmr1+rtmr2)
func (m *TdxMeasurements) CalculateMrImage() string {
	h := sha256.New()
	h.Write(m.MRTD)
	h.Write(m.RTMR1)
	h.Write(m.RTMR2)
	return hex.EncodeToString(h.Sum(nil))
}

func MeasureTdxQemu(fwData []byte, kernelData []byte, initrdData []byte, memorySize uint64, cpuCount uint8, kernelCmdline string, configuration string, debug bool) (*TdxMeasurements, error) {
	measurements := &TdxMeasurements{}

	// Get configuration-specific events
	configEvents, ok := machineConfigurations[configuration]
	if !ok {
		return nil, fmt.Errorf("unknown machine configuration: %s", configuration)
	}

	// Calculate MRTD
	// measurements.MRTD = tdvfMeta.computeMrtd(fwData, mrtdVariantTwoPass) TODO

	// RTMR0 calculations
	cfvImageHash, err := GetExpectedCfvSha384(fwData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute CFV hash: %w", err)
	}

	rtmr0Log := [][]byte{
		configEvents.TdHobHash,
		cfvImageHash,
		secureBootHash,
		pkHash,
		kekHash,
		dbHash,
		dbxHash,
		measureSha384([]byte{0x00, 0x00, 0x00, 0x00}), // Separator.
		configEvents.AcpiLoaderHash,
		configEvents.AcpiRsdpHash,
		configEvents.AcpiTablesHash,
		measureSha384([]byte{0x01, 0x00, 0x02, 0x00, 0x00, 0x00}), // BootOrder: 0001,0002,0000
		boot0001Hash,
		boot0002Hash,
		boot0000Hash,
	}
	measurements.RTMR0 = measureLog(rtmr0Log, debug, "RTMR0")

	// RTMR1 calculation
	ukiAuthHash, err := authenticode.Parse(bytes.NewReader(kernelData))
	if err != nil {
		return nil, err
	}

	kernelPEData := extractKernel(kernelData)
	kernelAuthHash, err := authenticode.Parse(bytes.NewReader(kernelPEData))
	if err != nil {
		return nil, err
	}

	rtmr1Log := [][]byte{
		measureSha384([]byte("Calling EFI Application from Boot Option")),
		measureSha384([]byte{0x00, 0x00, 0x00, 0x00}), // Separator.
		calculateUEFIDiskGUIDHash(),
		ukiAuthHash.Hash(crypto.SHA384),
		kernelAuthHash.Hash(crypto.SHA384),
		measureSha384([]byte("Exit Boot Services Invocation")),
		measureSha384([]byte("Exit Boot Services Returned with Success")),
	}
	measurements.RTMR1 = measureLog(rtmr1Log, debug, "RTMR1")

	// RTMR2 calculation
	rtmr2Log := [][]byte{
		measureTdxKernelCmdline(kernelCmdline),
		measureSha384(initrdData),
	}

	measurements.RTMR2 = measureLog(rtmr2Log, debug, "RTMR2")

	return measurements, nil
}
