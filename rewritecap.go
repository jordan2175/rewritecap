// Copyright 2014 Bret Jordan, All rights reserved.
//

package main

import (
	"code.google.com/p/getopt"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/pcapgo"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

var sOptPcapSrcFilename = getopt.StringLong("file", 'f', "", "Filename of the source PCAP file", "string")
var sOptPcapNewFilename = getopt.StringLong("filenew", 'n', "", "Filename for the new PCAP file", "string")
var sOptMacAddress = getopt.StringLong("mac", 0, "", "The MAC Address to change in AA:BB:CC:DD:EE:FF format", "string")
var sOptMacAddressNew = getopt.StringLong("macnew", 0, "", "The replacement MAC Address, required if mac is used", "string")
var sOptIPv4Address = getopt.StringLong("ip4", 0, "", "The IPv4 Address to change", "string")
var sOptIPv4AddressNew = getopt.StringLong("ip4new", 0, "", "The replacement IPv4 Address, required if ip4 is used", "string")

var iOptNewYear = getopt.IntLong("year", 'y', 0, "Rebase to Year (yyyy)", "int")
var iOptNewMonth = getopt.IntLong("month", 'm', 0, "Rebase to Month (mm)", "int")
var iOptNewDay = getopt.IntLong("day", 'd', 0, "Rebase to Day (dd)", "int")

var bOptHelp = getopt.BoolLong("help", 0, "Help")
var bOptVer = getopt.BoolLong("version", 0, "Version")

var iDebug = 1
var sVersion = "1.01"

//
//
//
// --------------------------------------------------------------------------------
// Function Main
// --------------------------------------------------------------------------------
func main() {
	getopt.HelpColumn = 25
	getopt.SetParameters("")
	getopt.Parse()

	if *bOptVer {
		fmt.Println("Version:", sVersion)
		os.Exit(0)
	}

	if *bOptHelp || (*sOptPcapSrcFilename == "" || *sOptPcapNewFilename == "") {
		getopt.Usage()
		os.Exit(0)
	}

	// Make sure if the user supplies one Layer2 option, that they also supply the other
	if (*sOptMacAddress != "" && *sOptMacAddressNew == "") || (*sOptMacAddressNew != "" && *sOptMacAddress == "") {
		getopt.Usage()
		os.Exit(0)
	}

	// Make sure if the user supplies one Layer3 option, that they also supply the other
	if (*sOptIPv4Address != "" && *sOptIPv4AddressNew == "") || (*sOptIPv4AddressNew != "" && *sOptIPv4Address == "") {
		getopt.Usage()
		os.Exit(0)
	}

	//
	//
	//
	// Figure out if there is a change needed for the date of each packet.  We will
	// compute the difference between what is in the first packet and what was passed
	// in via the command line arguments.
	iDiffYear := 0
	iDiffMonth := 0
	iDiffDay := 0

	pcapStartTimestamp := getFirstPacketTimestamp(*sOptPcapSrcFilename)

	if *iOptNewYear != 0 {
		iDiffYear = *iOptNewYear - pcapStartTimestamp.Year()
	}
	if *iOptNewMonth != 0 {
		iDiffMonth = *iOptNewMonth - int(pcapStartTimestamp.Month())
	}
	if *iOptNewDay != 0 {
		iDiffDay = *iOptNewDay - pcapStartTimestamp.Day()
	}

	if iDebug == 1 {
		fmt.Println("DEBUG: Y/M/D deltas", iDiffYear, iDiffMonth, iDiffDay)
	}
	// End compute date change

	//
	//
	//
	// Figure out if we need to change a layer 2 mac address
	userSuppliedMacAddress := make([]byte, 6, 6)
	userSuppliedMacAddressNew := make([]byte, 6, 6)
	if *sOptMacAddress != "" {
		var err error
		userSuppliedMacAddress, err = net.ParseMAC(*sOptMacAddress)

		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}
		if iDebug == 1 {
			fmt.Println("DEBUG: Passed in MAC Address to Change", *sOptMacAddress)
			fmt.Println("DEBUG: Parsed MAC Address to", userSuppliedMacAddress)
		}
	}
	if *sOptMacAddressNew != "" {
		var err error
		userSuppliedMacAddressNew, err = net.ParseMAC(*sOptMacAddressNew)

		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}
		if iDebug == 1 {
			fmt.Println("DEBUG: Passed in new MAC Address", *sOptMacAddressNew)
			fmt.Println("DEBUG: Parsed new MAC Address to", userSuppliedMacAddressNew)
		}
	}
	// End compute layer 2 change

	//
	//
	//
	// Figure out if we need to change a layer 3 IPv4 address
	userSuppliedIPv4Address := make([]byte, 4, 4)
	userSuppliedIPv4AddressNew := make([]byte, 4, 4)
	if *sOptIPv4Address != "" {
		// Since ParseIP returns a 16 byte slice (aka 128 bit address to accomodate IPv6)
		// just grab what we need
		userSuppliedIPv4Address = net.ParseIP(*sOptIPv4Address)[12:16]

		if iDebug == 1 {
			fmt.Println("DEBUG: Passed in IPv4 Address to Change", *sOptIPv4Address)
			fmt.Println("DEBUG: Parsed IPv4 Address to", userSuppliedIPv4Address)
		}
	}
	if *sOptIPv4AddressNew != "" {
		// Since ParseIP returns a 16 byte slice (aka 128 bit address to accomodate IPv6)
		// just grab what we need
		userSuppliedIPv4AddressNew = net.ParseIP(*sOptIPv4AddressNew)[12:16]

		if iDebug == 1 {
			fmt.Println("DEBUG: Passed in new IPv4 Address", *sOptIPv4AddressNew)
			fmt.Println("DEBUG: Parsed new IPv4 Address to", userSuppliedIPv4AddressNew)
		}
	}
	// End compute layer 3 change

	//
	//
	//
	// Get a handle to the PCAP source file so we can loop through each packet and make
	// changes as needed.
	handle, err1 := pcap.OpenOffline(*sOptPcapSrcFilename)
	if err1 != nil {
		fmt.Println(err1)
		os.Exit(0)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Create file handle to write to
	fileHandle, err2 := os.Create(*sOptPcapNewFilename)
	if err2 != nil {
		fmt.Println(err2)
		os.Exit(0)
	}
	writer := pcapgo.NewWriter(fileHandle)
	writer.WriteFileHeader(65535, handle.LinkType())

	fmt.Println("Each '.' represents 1000 packets converted.")

	//
	//
	//
	// Loop through every packet and update them as needed writing the changes out to a new file
	iCounter := 0
	for packet := range packetSource.Packets() {
		if iDebug == 1 {
			fmt.Println("DEBUG: ", "----------------------------------------")
		}

		//
		//
		//
		// Make changes to the time stamp of this packet if a change is needed / requested
		if iDiffYear != 0 || iDiffMonth != 0 || iDiffDay != 0 {
			ts := packet.Metadata().CaptureInfo.Timestamp
			if iDebug == 1 {
				fmt.Println("DEBUG: Current timestamp", ts)
			}
			tsNew := ts.AddDate(iDiffYear, iDiffMonth, iDiffDay)
			if iDebug == 1 {
				fmt.Println("DEBUG: Updated timestamp", tsNew)
			}
			packet.Metadata().CaptureInfo.Timestamp = tsNew
		}

		//
		//
		//
		// Lets compare the mac address supplied with the one in the pcap file for both
		// the DST MAC and SRC MAC but only if a MAC address is supplied as an ARG
		if *sOptMacAddress != "" {
			dstMacAddressFromPacket := packet.LinkLayer().LayerContents()[0:6]
			bDstMacAddressMatch := areByteSlicesEqual(dstMacAddressFromPacket, userSuppliedMacAddress)
			if bDstMacAddressMatch {
				if iDebug == 1 {
					fmt.Println("There is a match on the DST MAC Address, updating", makePrettyMacAddress(userSuppliedMacAddress), "to", makePrettyMacAddress(userSuppliedMacAddressNew))
				}

				for i := 0; i < 6; i++ {
					packet.LinkLayer().LayerContents()[i] = userSuppliedMacAddressNew[i]
				}
			}

			srcMacAddressFromPacket := packet.LinkLayer().LayerContents()[6:12]
			bSrcMacAddressMatch := areByteSlicesEqual(srcMacAddressFromPacket, userSuppliedMacAddress)
			if bSrcMacAddressMatch {
				if iDebug == 1 {
					fmt.Println("There is a match on the SRC MAC Address, updating", makePrettyMacAddress(userSuppliedMacAddress), "to", makePrettyMacAddress(userSuppliedMacAddressNew))
				}

				j := 0
				for i := 6; i < 12; i++ {
					packet.LinkLayer().LayerContents()[i] = userSuppliedMacAddressNew[j]
					j++
				}
			}
		}
		// End Update Layer 2 MAC Addresses

		if *sOptIPv4Address != "" {
			if packet.NetworkLayer().LayerContents()[0] == 69 {
				fmt.Println("DEBUG: Found a Native Frame")
				srcIPv4AddressFromPacket := packet.NetworkLayer().LayerContents()[12:16]
				bSrcIPv4AddressMatch := areByteSlicesEqual(srcIPv4AddressFromPacket, userSuppliedIPv4Address)
				if bSrcIPv4AddressMatch {
					if iDebug == 1 {
						fmt.Println("DEBUG: There is a match on the SRC IPv4 Address, updating", userSuppliedIPv4Address, "to", userSuppliedIPv4AddressNew)
					}
					j := 0
					for i := 12; i < 16; i++ {
						packet.NetworkLayer().LayerContents()[i] = userSuppliedIPv4AddressNew[j]
						j++
					}
				}

				dstIPv4AddressFromPacket := packet.NetworkLayer().LayerContents()[16:20]
				bDstIPv4AddressMatch := areByteSlicesEqual(dstIPv4AddressFromPacket, userSuppliedIPv4Address)
				if bDstIPv4AddressMatch {
					if iDebug == 1 {
						fmt.Println("DEBUG: There is a match on the DST IPv4 Address, updating", userSuppliedIPv4Address, "to", userSuppliedIPv4AddressNew)
					}
					j := 0
					for i := 16; i < 20; i++ {
						packet.NetworkLayer().LayerContents()[i] = userSuppliedIPv4AddressNew[j]
						j++
					}
				}
			}
			// Need to add support for other types of packets like ARP, 802.1Q etc, things other than type 69
		}

		//
		//
		//
		// Write the packet out to the new file
		writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

		// Write some output to the screen so users know we are doing something
		iCounter++
		if iCounter%1000 == 0 {
			fmt.Print(".")
			if iCounter%80000 == 0 {
				fmt.Print("\n")
			}
		}
	} // End loop through every packet

	fileHandle.Close()
	fmt.Println("\nNumber of packets processed:", iCounter)

} // main()

//
//
//
// --------------------------------------------------------------------------------
// getFirstPacketTimestamp
// --------------------------------------------------------------------------------
// We need to open the pcap file and read the timestamp from the first packet so
// that we can figure out an offset for all future packets.  This will address the
// problem of the pcap spanning multiple days, months, years  as we will always
// add the same amount of offset to each packet.
func getFirstPacketTimestamp(sFilename string) time.Time {
	handle, err := pcap.OpenOffline(sFilename)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	_, packetHeaderInfo, _ := handle.ReadPacketData()
	ts := packetHeaderInfo.Timestamp
	if iDebug == 1 {
		fmt.Println("DEBUG: Timestamp of first packet", ts)
	}
	return ts
}

//
//
//
// --------------------------------------------------------------------------------
//  makePrettyMacAddress
// --------------------------------------------------------------------------------
// This function will create a human readable MAC address in upper case using
// the : notation between octets
func makePrettyMacAddress(mac []byte) string {
	sMAC := strings.ToUpper(hex.EncodeToString(mac))
	var sNewMAC string

	// This will add a ":" after ever ODD index value but not on the last one
	for i, value := range sMAC {
		sNewMAC += string(value)
		if i%2 != 0 && i%11 != 0 {
			sNewMAC += ":"
		}
	}
	if iDebug == 2 {
		fmt.Println("DEBUG: MAC Address", sNewMAC)
	}

	return sNewMAC
}

//
//
//
// --------------------------------------------------------------------------------
//  areByteSlicesEqual
// --------------------------------------------------------------------------------
// Compare two byte slices to see if they are the same
func areByteSlicesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
