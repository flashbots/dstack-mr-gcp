package main

import (
	"bytes"
	"debug/pe"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/kvinwang/dstack-mr/internal"
)

const (
	GB = 1024 * 1024 * 1024 // in bytes
	MB = 1024 * 1024
)

type measurementOutput struct {
	RTMR1        string   `json:"rtmr1"`
	RTMR2        string   `json:"rtmr2"`
	RTMR3        string   `json:"rtmr3"`
	RTMR0        []string `json:"rtmr0"`
	MRTD         []string `json:"mrtd"`
	MRConfigID   string   `json:"mrconfigid"`
	XFAM         string   `json:"xfam"`
	TDAttributes string   `json:"tdattributes"`
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

func main() {
	var (
		// fwPath        string
		ukiPath       string
		memorySize    memoryValue
		cpuCountUint  uint
		debug         bool
		configuration string
	)

	// flag.StringVar(&fwPath, "fw", "", "Path to firmware file")
	flag.StringVar(&ukiPath, "uki", "", "Path to UKI (Unified Kernel Image) file")
	flag.Var(&memorySize, "memory", "Memory size (e.g., 512M, 1G, 2G)")
	flag.UintVar(&cpuCountUint, "cpu", 1, "Number of CPUs")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.StringVar(&configuration, "config", "", "Machine configuration (e.g., c3-standard-4). If omitted, generates measurements for all configurations")
	flag.Parse()

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

	// Download firmware data from GCS bucket
	fwURL := fmt.Sprintf("https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/%s.fd", internal.LatestFirmwareFile)
	resp, err := http.Get(fwURL)
	if err != nil {
		fmt.Printf("Error downloading firmware file: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fwData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading firmware data: %v\n", err)
		os.Exit(1)
	}

	// Determine which configurations to process
	var configurations []string
	if configuration != "" {
		configurations = []string{configuration}
	} else {
		configurations = internal.GetAllConfigurations()
	}

	var rtmr0s []string
	// Todo: compute
	var mrtds []string = []string{internal.LatestMRTD}

	// Todo: loop across MRTDS
	for _, config := range configurations {
		// Calculate measurements for this configuration
		measurements, err := internal.MeasureTdxQemu(fwData, ukiData, initrdData, uint64(memorySize), uint8(cpuCountUint), kernelCmdline, config, debug)
		if err != nil {
			fmt.Printf("Error calculating measurements for %s: %v\n", config, err)
			os.Exit(1)
		}

		rtmr0s = append(rtmr0s, fmt.Sprintf("%x", measurements.RTMR0))
	}

	// Use the last measurements for RTMR1/RTMR2
	measurements, _ := internal.MeasureTdxQemu(fwData, ukiData, initrdData, uint64(memorySize), uint8(cpuCountUint), kernelCmdline, configurations[0], debug)

	output := measurementOutput{
		RTMR1:        fmt.Sprintf("%x", measurements.RTMR1),
		RTMR2:        fmt.Sprintf("%x", measurements.RTMR2),
		RTMR0:        rtmr0s,
		MRTD:         mrtds,
		XFAM:         internal.XFAM,
		TDAttributes: internal.TDAttributes,
		MRConfigID:   internal.Empty,
		RTMR3:        internal.Empty,
	}
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Printf("Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonData))
}
