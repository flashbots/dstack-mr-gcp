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
	"strings"

	"github.com/kvinwang/dstack-mr/internal"
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
		// fwPath  string
		ukiPath string
		debug   bool
		config  string
	)

	// flag.StringVar(&fwPath, "fw", "", "Path to firmware file")
	flag.StringVar(&ukiPath, "uki", "", "Path to UKI (Unified Kernel Image) file")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.StringVar(&config, "config", "", "Machine configurations (comma-separated, e.g., c3-standard-4,c3-standard-22)")
	flag.Parse()

	var configurations []string
	if config != "" {
		configurations = strings.Split(config, ",")
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

	// Download and measure each firmware variant
	var rtmr0s []string
	var mrtds []string
	for _, fw := range internal.FirmwareMRTDs {
		fwURL := fmt.Sprintf("https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/%s.fd", fw.FirmwareFile)
		resp, err := http.Get(fwURL)
		if err != nil {
			fmt.Printf("Error downloading firmware file %s: %v\n", fw.FirmwareFile[:16], err)
			os.Exit(1)
		}
		fwData, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Printf("Error reading firmware data: %v\n", err)
			os.Exit(1)
		}

		rtmr0Hashes, err := internal.MeasureRTMR0(fwData, configurations, debug)
		if err != nil {
			fmt.Printf("Error calculating RTMR0: %v\n", err)
			os.Exit(1)
		}
		for _, h := range rtmr0Hashes {
			rtmr0s = append(rtmr0s, fmt.Sprintf("%x", h))
		}
		mrtds = append(mrtds, fw.MRTD)
	}

	// Calculate firmware-independent measurements (RTMR1, RTMR2)
	rtmr1, rtmr2, err := internal.MeasureRTMR1And2(ukiData, initrdData, kernelCmdline, debug)
	if err != nil {
		fmt.Printf("Error calculating measurements: %v\n", err)
		os.Exit(1)
	}

	output := measurementOutput{
		RTMR1:        fmt.Sprintf("%x", rtmr1),
		RTMR2:        fmt.Sprintf("%x", rtmr2),
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
