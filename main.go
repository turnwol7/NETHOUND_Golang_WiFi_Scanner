package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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

	// Open the interface for capturing
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Failed to open interface:", err)
	}
	defer handle.Close()

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
	timeout := time.After(5 * time.Second)
	deviceCount := 0
	seenMACs := make(map[string]bool)

	for {
		select {
		case packet := <-packetSource.Packets():
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply {
					mac := net.HardwareAddr(arp.SourceHwAddress)
					macStr := mac.String()
					
					// Only print if we haven't seen this MAC address before
					if !seenMACs[macStr] {
						deviceCount++
						seenMACs[macStr] = true
						fmt.Printf("%d. IP: %-15s\tMAC: %s\n",
							deviceCount,
							net.IP(arp.SourceProtAddress),
							mac)
					}
				}
			}
		case <-timeout:
			fmt.Printf("\nTotal unique devices found: %d\n", deviceCount)
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

func main() {
	fmt.Println("Starting network scan...")
	fmt.Println("======================")
	scanNetwork()
	fmt.Println("\nScan complete!")
}
