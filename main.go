package main

import (
	"bytes"
	"debug/pe"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/kvinwang/dstack-mr/internal"
)

const (
	GB = 1024 * 1024 * 1024 // in bytes
	MB = 1024 * 1024
)

type measurementOutput struct {
	RTMR1      string `json:"rtmr1"`
	RTMR2      string `json:"rtmr2"`
	WorkloadID string `json:"workloadId"`
}

var workloadFooter = make([]byte, 112) // RTMR3(48) + MRCONFIGID(48) + TdAttributes(8) + xFAM(8)

var knownKeyProviders = map[string]string{
	"sgx-v0": "0x4888adb026ff91c1320c4f544a9f5d9e0561e13fc64947a10aa1556d0071b2cc",
	"none":   "0x3369c4d32b9f1320ebba5ce9892a283127b7e96e1d511d7f292e5d9ed2c10b8c",
}

// parseMemorySize parses a human readable memory size (e.g., "1G", "512M") into bytes
func parseMemorySize(size string) (uint64, error) {
	size = strings.TrimSpace(strings.ToUpper(size))
	if len(size) == 0 {
		return 0, fmt.Errorf("empty memory size")
	}

	// Check if the input is purely numeric (no unit)
	if _, err := strconv.ParseUint(size, 10, 64); err == nil {
		// If it's a valid number with no unit, interpret as MB
		num, _ := strconv.ParseUint(size, 10, 64)
		return num, nil
	}

	// Get the unit (last character)
	unit := size[len(size)-1:]
	// Get the number (everything except the last character)
	numStr := size[:len(size)-1]

	// Parse the number
	num, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid memory size number: %v", err)
	}

	// Convert to bytes based on unit
	switch unit {
	case "G":
		return num * GB, nil // Convert GB to bytes
	case "M":
		return num * MB, nil // Convert MB to bytes
	default:
		return 0, fmt.Errorf("invalid memory unit '%s', must be one of: G, M", unit)
	}
}

type memoryValue uint64

func (m *memoryValue) String() string {
	m_bytes := uint64(*m)
	if m_bytes >= GB && m_bytes%GB == 0 {
		return fmt.Sprintf("%dG", m_bytes/GB)
	}
	if m_bytes >= MB && m_bytes%MB == 0 {
		return fmt.Sprintf("%dM", m_bytes/MB)
	}
	return fmt.Sprintf("%d", m_bytes)
}

func (m *memoryValue) Set(value string) error {
	m_bytes, err := parseMemorySize(value)
	if err != nil {
		return err
	}
	*m = memoryValue(m_bytes)
	return nil
}

func extractUKISections(ukiData []byte) (string, []byte, error) {
	// Create a reader from the UKI data
	reader := bytes.NewReader(ukiData)

	// Parse as PE file
	peFile, err := pe.NewFile(reader)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse UKI as PE file: %w", err)
	}

	// Extract cmdline section
	cmdlineSection := peFile.Section(".cmdline")
	if cmdlineSection == nil {
		return "", nil, fmt.Errorf("no .cmdline section found in UKI")
	}

	cmdlineData, err := cmdlineSection.Data()
	if err != nil {
		return "", nil, fmt.Errorf("failed to read .cmdline section: %w", err)
	}

	// Convert cmdline to string, removing any trailing null bytes
	kernelCmdline := strings.TrimRight(string(cmdlineData), "\x00")

	var initrdData []byte
	initrdSection := peFile.Section(".initrd")
	if initrdSection != nil {
		initrdData, err = initrdSection.Data()
		if err != nil {
			return "", nil, fmt.Errorf("failed to read .initrd section: %w", err)
		}

		// Trim initrdData to the actual initrd size
		initrdData = initrdData[:initrdSection.VirtualSize]
	}

	return kernelCmdline, initrdData, nil
}

func generateWorkloadID(rtmr1, rtmr2 []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(rtmr1)
	hash.Write(rtmr2)
	return hash.Sum(workloadFooter)
}

func main() {
	const defaultMrKeyProvider = "0x0000000000000000000000000000000000000000000000000000000000000000"
	var (
		fwPath        string
		ukiPath       string
		memorySize    memoryValue
		cpuCountUint  uint
		debug         bool
		mrKeyProvider string = defaultMrKeyProvider
	)

	flag.StringVar(&fwPath, "fw", "", "Path to firmware file")
	flag.StringVar(&ukiPath, "uki", "", "Path to UKI (Unified Kernel Image) file")
	flag.Var(&memorySize, "memory", "Memory size (e.g., 512M, 1G, 2G)")
	flag.UintVar(&cpuCountUint, "cpu", 1, "Number of CPUs")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.StringVar(&mrKeyProvider, "mrkp", defaultMrKeyProvider, "Measurement of key provider")
	flag.Parse()

	// If the mrKeyProvider is in the knownKeyProviders, replace it with the value
	if knownKeyProvider, ok := knownKeyProviders[mrKeyProvider]; ok {
		mrKeyProvider = knownKeyProvider
	}

	ukiData, err := os.ReadFile(ukiPath)
	if err != nil {
		fmt.Printf("Error reading UKI file: %v\n", err)
		os.Exit(1)
	}

	// Extract cmdline and initrd from UKI
	kernelCmdline, initrdData, err := extractUKISections(ukiData)
	if err != nil {
		fmt.Printf("Error extracting sections from UKI: %v\n", err)
		os.Exit(1)
	}

	// Read firmware file
	/*fwData, err := os.ReadFile(fwPath)
	if err != nil {
		fmt.Printf("Error reading firmware file: %v\n", err)
		os.Exit(1)
	}*/
	fwData := []byte{} // TODO

	// Calculate measurements
	measurements, err := internal.MeasureTdxQemu(fwData, ukiData, initrdData, uint64(memorySize), uint8(cpuCountUint), kernelCmdline, debug)
	if err != nil {
		fmt.Printf("Error calculating measurements: %v\n", err)
		os.Exit(1)
	}

	var workloadId = generateWorkloadID(measurements.RTMR1, measurements.RTMR2)

	output := measurementOutput{
		RTMR1:      fmt.Sprintf("%x", measurements.RTMR1),
		RTMR2:      fmt.Sprintf("%x", measurements.RTMR2),
		WorkloadID: fmt.Sprintf("%x", workloadId),
	}
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Printf("Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonData))
}
