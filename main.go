package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"context"
	"regexp"

	"math"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type NetworkDevice struct {
	IP         string
	MAC        string
	Vendor     string
	OpenPorts  []int
	Hostname   string
	DeviceType string
	Services   map[int]string
	Banners    map[int]string
	Signal     SignalInfo
}

type SignalInfo struct {
	RSSI     int
	Distance float64
	Samples  []int
}

const (
	// Environmental factor (2.0 to 4.0)
	// 2.0 for free space
	// 2.7 for indoor office
	// 3.0 for indoor home
	// 3.5 for urban area
	environmentalFactor = 2.7

	// Reference RSSI at 1 meter distance (calibration value)
	referenceRSSI = -40

	// Number of samples to average
	sampleSize = 5
)

func printBanner() {
	banner := `
    ███╗   ██╗███████╗████████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ 
    ████╗  ██║██╔════╝╚══██╔══╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
    ██╔██╗ ██║█████╗     ██║   ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
    ██║╚██╗██║██╔══╝     ██║   ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
    ██║ ╚████║███████╗   ██║   ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 
                      /\___/\
                     (  o o  )
                     (  =^=  ) 
                      (____))_)━━━━━━━╮
                        ||  ||        |
                        ||  ||     [NETWORK]
                        \|  \|     [SNIFFER]
                         |   |        |
                        (___|__)━━━━━━╯
    =================== Network Sniffer v0.1 ===================
    `
	fmt.Println(banner)
}

func downloadOUIDatabase() error {
	fmt.Println("Downloading IEEE OUI database...")

	resp, err := http.Get("https://standards-oui.ieee.org/oui/oui.txt")
	if err != nil {
		return fmt.Errorf("failed to fetch OUI database: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch OUI database: %s", resp.Status)
	}

	// Print a single message indicating that the data has been fetched
	fmt.Println("Successfully fetched OUI data from the website.")

	// Create output file
	file, err := os.Create("oui.csv")
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	validEntries := 0
	scanner := bufio.NewScanner(resp.Body)

	var currentOUI string
	for scanner.Scan() {
		line := scanner.Text()
		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Check for OUI lines
		if strings.Contains(line, "(hex)") {
			parts := strings.Split(line, "(hex)")
			if len(parts) > 0 {
				currentOUI = strings.TrimSpace(parts[0])
				// Clean up the OUI format (remove dashes)
				currentOUI = strings.ReplaceAll(currentOUI, "-", "")
			}
		} else if strings.Contains(line, "(base 16)") {
			// This line contains the organization name
			parts := strings.Split(line, "(base 16)")
			if len(parts) > 1 {
				organization := strings.TrimSpace(parts[1])
				// Write to CSV
				if err := writer.Write([]string{currentOUI, organization}); err != nil {
					return fmt.Errorf("error writing to CSV: %v", err)
				}
				validEntries++
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading database: %v", err)
	}

	if validEntries == 0 {
		fmt.Println("Warning: No valid entries found in the OUI database.")
	} else {
		fmt.Printf("OUI database downloaded successfully with %d entries.\n", validEntries)
	}

	return nil
}

// Helper function to check if a string is hexadecimal
func isHexString(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, char := range s {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func loadOUIDatabase() map[string]string {
	vendors := make(map[string]string)

	// Try to download/update the database
	err := downloadOUIDatabase()
	if err != nil {
		log.Printf("Warning: Could not download vendor database: %v", err)
		return vendors
	}

	file, err := os.Open("oui.csv") // Load from CSV
	if err != nil {
		log.Printf("Warning: Could not load vendor database: %v", err)
		return vendors
	}
	defer file.Close()

	reader := csv.NewReader(file)
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		if len(record) >= 2 {
			vendors[strings.ToUpper(record[0])] = record[1]
		}
	}

	// Optionally, you can print a summary instead of each entry
	fmt.Printf("Loaded OUI Database with %d entries.\n", len(vendors))

	return vendors
}

func identifyService(ip string, port int) string {
	common := map[int]string{
		22:    "SSH",
		80:    "HTTP",
		443:   "HTTPS",
		445:   "SMB",
		3389:  "RDP",
		5000:  "UPnP",
		8080:  "HTTP-Alt",
		548:   "AFP (Apple Filing)",
		5353:  "mDNS",
		62078: "iPhone-Sync",
		137:   "NetBIOS",
		139:   "NetBIOS",
		53:    "DNS",
		88:    "Kerberos",
		631:   "IPP (Printing)",
		9100:  "Printer Raw",
	}

	if service, ok := common[port]; ok {
		return service
	}
	return "unknown"
}

func grabBanner(ip string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), time.Second*2)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Send different requests based on port
	switch port {
	case 80, 8080, 443:
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
	case 22:
		// SSH will send banner automatically
	default:
		// For unknown services, just try to read
	}

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Second * 2))
	n, _ := conn.Read(buffer)
	return cleanBanner(string(buffer[:n]))
}

func cleanBanner(banner string) string {
	// Remove non-printable characters
	re := regexp.MustCompile(`[^\x20-\x7E\n]`)
	banner = re.ReplaceAllString(banner, "")
	// Limit length
	if len(banner) > 100 {
		banner = banner[:100] + "..."
	}
	return strings.TrimSpace(banner)
}

func guessDeviceType(vendor string, ports []int, hostname string) string {
	hostname = strings.ToLower(hostname)
	macPrefix := strings.ToLower(vendor)

	// Check hostname patterns
	switch {
	case strings.Contains(hostname, "iphone"):
		return "iPhone"
	case strings.Contains(hostname, "ipad"):
		return "iPad"
	case strings.Contains(hostname, "macbook"):
		return "MacBook"
	case strings.Contains(hostname, "android"):
		return "Android Device"
	case strings.Contains(hostname, "windows"):
		return "Windows PC"
	case strings.Contains(hostname, "raspberry"):
		return "Raspberry Pi"
	}

	// Check vendor patterns
	switch {
	case strings.Contains(macPrefix, "apple"):
		return "Apple Device"
	case strings.Contains(macPrefix, "google"):
		return "Google Device"
	case strings.Contains(macPrefix, "samsung"):
		return "Samsung Device"
	case strings.Contains(macPrefix, "ubiquiti"):
		return "Ubiquiti Router/AP"
	}

	// Add more checks for common IoT devices
	if containsAny(ports, []int{80, 443}) {
		return "Web-enabled Device"
	}
	if containsAny(ports, []int{554}) {
		return "IP Camera"
	}
	if containsAny(ports, []int{9100, 631}) {
		return "Printer"
	}

	return "Unknown Device"
}

func scanPorts(ip string) ([]int, map[int]string, map[int]string) {
	var openPorts []int
	services := make(map[int]string)
	banners := make(map[int]string)
	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Common ports to scan
	commonPorts := []int{
		20, 21, 22, 23, 25, 53, 80, 88, 110, 123, 137, 138, 139, 143, 443, 445,
		548, 631, 3389, 5000, 5353, 8080, 8443, 9100, 62078,
	}

	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				mutex.Lock()
				openPorts = append(openPorts, p)
				services[p] = identifyService(ip, p)
				banner := grabBanner(ip, p)
				if banner != "" {
					banners[p] = banner
				}
				mutex.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return openPorts, services, banners
}

func containsAny(haystack []int, needles []int) bool {
	for _, h := range haystack {
		for _, n := range needles {
			if h == n {
				return true
			}
		}
	}
	return false
}

func discoverMDNSServices(ctx context.Context) map[string]string {
	deviceNames := make(map[string]string)

	entries, err := net.LookupAddr("224.0.0.251:5353")
	if err != nil {
		return deviceNames
	}

	for _, entry := range entries {
		// Try to resolve the IP address
		ips, err := net.LookupHost(entry)
		if err != nil {
			continue
		}

		// Map the first IP to the hostname
		if len(ips) > 0 {
			hostname := strings.TrimSuffix(entry, ".")
			hostname = strings.TrimSuffix(hostname, ".local")
			deviceNames[ips[0]] = hostname
		}
	}

	return deviceNames
}

func calculateDistance(rssi int) float64 {
	// Free space path loss formula
	// distance = 10 ^ ((|RSSI| - |Reference RSSI|) / (10 * n))
	// where n is the environmental factor

	absRSSI := math.Abs(float64(rssi))
	absRef := math.Abs(float64(referenceRSSI))
	exp := (absRSSI - absRef) / (10 * environmentalFactor)

	return math.Pow(10, exp)
}

func averageRSSI(samples []int) int {
	if len(samples) == 0 {
		return 0
	}

	sum := 0
	for _, rssi := range samples {
		sum += rssi
	}
	return sum / len(samples)
}

// First, check if we can enable monitor mode
func enableMonitorMode(iface string) error {
	// Use iwconfig/airmon-ng to enable monitor mode
	cmd := exec.Command("sudo", "airmon-ng", "start", iface)
	return cmd.Run()
}

func getRSSI() (SignalInfo, error) {
	cmd := exec.Command("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I")
	output, err := cmd.Output()
	if err != nil {
		return SignalInfo{}, err
	}

	var signalInfo SignalInfo
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse RSSI
		if strings.HasPrefix(line, "agrCtlRSSI:") {
			rssiStr := strings.TrimPrefix(line, "agrCtlRSSI:")
			rssi, err := strconv.Atoi(strings.TrimSpace(rssiStr))
			if err == nil {
				signalInfo.RSSI = rssi
				signalInfo.Samples = append(signalInfo.Samples, rssi)
				signalInfo.Distance = calculateDistance(rssi)
			}
		}

		// You might also want to capture noise level for better accuracy
		if strings.HasPrefix(line, "agrCtlNoise:") {
			noiseStr := strings.TrimPrefix(line, "agrCtlNoise:")
			noise, err := strconv.Atoi(strings.TrimSpace(noiseStr))
			if err == nil {
				// Signal-to-Noise Ratio could be used for better distance estimation
				_ = noise // store this if you want to use it later
			}
		}
	}

	return signalInfo, nil
}

// Add this function to continuously monitor RSSI
func monitorRSSI(updateInterval time.Duration) chan SignalInfo {
	signalChan := make(chan SignalInfo)

	go func() {
		for {
			if signal, err := getRSSI(); err == nil {
				signalChan <- signal
			}
			time.Sleep(updateInterval)
		}
	}()

	return signalChan
}

func scanNetwork() {
	// List all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal("Failed to get interfaces:", err)
	}

	fmt.Println("Available network interfaces:")
	for _, iface := range interfaces {
		fmt.Printf("- %s (MAC: %s)\n", iface.Name, iface.HardwareAddr)
	}

	// Get the WiFi interface (usually en0 on Mac)
	iface, err := net.InterfaceByName("en0")
	if err != nil {
		log.Fatal("Failed to get interface:", err)
	}

	// Get interface addresses
	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatal("Failed to get interface addresses:", err)
	}

	// Find IPv4 address and subnet
	var subnet *net.IPNet
	fmt.Println("\nInterface addresses:")
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			fmt.Printf("- %s\n", ipnet.String())
			if ipnet.IP.To4() != nil {
				subnet = ipnet
			}
		}
	}

	if subnet == nil {
		log.Fatal("No IPv4 address found")
	}

	fmt.Printf("\nScanning subnet: %s\n", subnet.String())

	// Remove monitor mode attempt and wireless filter
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Just set ARP filter
	err = handle.SetBPFFilter("arp")
	if err != nil {
		log.Fatal(err)
	}

	// Start RSSI monitoring quietly
	signalChan := monitorRSSI(1 * time.Second)
	var currentSignal SignalInfo

	fmt.Println("\nScanning network and monitoring signal strength...")
	fmt.Println("------------------------------------------------")

	// Create and send ARP request
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(subnet.IP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}

	// Send ARP request for each IP in subnet
	fmt.Println("\nSending ARP requests...")
	ipCount := 0
	for ip := subnet.IP.Mask(subnet.Mask); subnet.Contains(ip); inc(ip) {
		ipCount++
		arp.DstProtAddress = []byte(ip.To4())

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			log.Printf("Error sending ARP to %v: %v", ip, err)
		}
	}
	fmt.Printf("Sent ARP requests to %d IP addresses\n", ipCount)

	// Read responses
	fmt.Println("\nDiscovered devices:")
	fmt.Println("------------------")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(15 * time.Second)
	deviceCount := 0
	seenMACs := make(map[string]bool)
	vendors := loadOUIDatabase()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	deviceNames := discoverMDNSServices(ctx)

	// Collect device types for CSV
	devicesToWrite := [][]string{}

	for {
		select {
		case signal := <-signalChan:
			currentSignal = signal
			// Only print RSSI if it changed significantly (e.g., more than 2 dBm)
			if math.Abs(float64(signal.RSSI-currentSignal.RSSI)) > 2 {
				fmt.Printf("\rSignal strength: %d dBm (≈%.1f meters from router)   ",
					signal.RSSI, signal.Distance)
			}

		case packet := <-packetSource.Packets():
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply {
					mac := net.HardwareAddr(arp.SourceHwAddress)
					macStr := mac.String()
					ipStr := net.IP(arp.SourceProtAddress).String()

					if !seenMACs[macStr] {
						deviceCount++
						seenMACs[macStr] = true

						oui := strings.ToUpper(strings.Replace(macStr[0:8], ":", "", -1))
						vendor := vendors[oui]
						if vendor == "" {
							vendor = "Unknown"
						}

						openPorts, services, banners := scanPorts(ipStr)
						hostname := deviceNames[ipStr]
						deviceType := guessDeviceType(vendor, openPorts, hostname)

						device := NetworkDevice{
							IP:         ipStr,
							MAC:        macStr,
							Vendor:     vendor,
							OpenPorts:  openPorts,
							Hostname:   hostname,
							DeviceType: deviceType,
							Services:   services,
							Banners:    banners,
							Signal:     currentSignal,
						}

						// Add signal information to the device
						device.Signal = currentSignal

						// Update your device output to include signal strength
						fmt.Printf("\nDevice %d:\n", deviceCount)
						fmt.Printf("  IP: %s\n", device.IP)
						fmt.Printf("  MAC: %s\n", device.MAC)
						fmt.Printf("  Vendor: %s\n", device.Vendor)
						fmt.Printf("  OUI: %s\n", oui)
						if device.Hostname != "" {
							fmt.Printf("  Hostname: %s\n", device.Hostname)
						}
						if device.Signal.RSSI != 0 {
							fmt.Printf("  Signal: %d dBm (%s)\n",
								device.Signal.RSSI, getSignalQuality(device.Signal.RSSI))
							fmt.Printf("  Distance: %.1f meters\n", device.Signal.Distance)
						}

						// Collect device types for CSV
						devicesToWrite = append(devicesToWrite, []string{device.IP, device.MAC, device.Vendor, device.DeviceType})
					}
				}
			}
		case <-timeout:
			fmt.Printf("\n\nScan complete. Found %d devices.\n", deviceCount)
			// Write collected device types to CSV after scanning
			if err := writeCSV(devicesToWrite); err != nil {
				log.Printf("Error writing to CSV: %v", err)
			}
			return
		}
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Add this helper function for signal quality
func getSignalQuality(rssi int) string {
	switch {
	case rssi >= -50:
		return "Excellent"
	case rssi >= -60:
		return "Very Good"
	case rssi >= -70:
		return "Good"
	case rssi >= -80:
		return "Fair"
	default:
		return "Poor"
	}
}

func writeCSV(data [][]string) error {
	file, err := os.Create("oui.csv")
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, record := range data {
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	printBanner()
	fmt.Println("Starting network scan...")
	fmt.Println("======================")
	scanNetwork()
	fmt.Println("\nScan complete!")

}
