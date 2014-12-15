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
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var sOptPcapSrcFilename = getopt.StringLong("file", 'f', "", "Filename of the source PCAP file", "string")
var sOptPcapNewFilename = getopt.StringLong("newfile", 'n', "", "Filename for the new PCAP file", "string")
var sOptMacAddress = getopt.StringLong("mac", 0, "", "The MAC Address to change in AA:BB:CC:DD:EE:FF format", "string")
var sOptNewMacAddress = getopt.StringLong("newmac", 0, "", "The replacement MAC Address, required if mac is used", "string")

var iOptNewYear = getopt.IntLong("year", 'y', 0, "Rebase to Year (yyyy)", "int")
var iOptNewMonth = getopt.IntLong("month", 'm', 0, "Rebase to Month (mm)", "int")
var iOptNewDay = getopt.IntLong("day", 'd', 0, "Rebase to Day (dd)", "int")

var bOptHelp = getopt.BoolLong("help", 0, "Help")
var bOptVer = getopt.BoolLong("version", 0, "Version")

var iCounter = 0
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
	if (*sOptMacAddress != "" && *sOptNewMacAddress == "") || (*sOptNewMacAddress != "" && *sOptMacAddress == "") {
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
	userSuppliedNewMacAddress := make([]byte, 6, 6)
	if *sOptMacAddress != "" {
		if iDebug == 1 {
			fmt.Println("DEBUG: Passed in MAC Address to Change", *sOptMacAddress)
		}
		var err error
		userSuppliedMacAddress, err = net.ParseMAC(*sOptMacAddress)
		if err != nil {
			log.Fatal(err)
		}
		if iDebug == 1 {
			fmt.Println("DEBUG: Parsed MAC Address to", userSuppliedMacAddress)
		}
	}
	if *sOptNewMacAddress != "" {
		if iDebug == 1 {
			fmt.Println("DEBUG: Passed in MAC Address to Change", *sOptNewMacAddress)
		}
		var err error
		userSuppliedNewMacAddress, err = net.ParseMAC(*sOptNewMacAddress)
		if err != nil {
			log.Fatal(err)
		}
		if iDebug == 1 {
			fmt.Println("DEBUG: Parsed MAC Address to", userSuppliedNewMacAddress)
		}
	}
	// End compute layer 2 change

	//
	//
	//
	// Get a handle to the PCAP source file so we can loop through each packet and make
	// changes as needed.
	handle, err1 := pcap.OpenOffline(*sOptPcapSrcFilename)
	if err1 != nil {
		log.Fatal(err1)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Create file handle to write to
	fileHandle, err2 := os.Create(*sOptPcapNewFilename)
	if err2 != nil {
		log.Fatal(err2)
	}
	writer := pcapgo.NewWriter(fileHandle)
	writer.WriteFileHeader(65535, handle.LinkType())

	fmt.Println("Each '.' represents 1000 packets converted.")

	//
	//
	//
	// Loop through every packet and update them as needed writing the changes out to a new file
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
					fmt.Println("There is a match on the DST MAC Address, updating", makePrettyMacAddress(userSuppliedMacAddress), "to", makePrettyMacAddress(userSuppliedNewMacAddress))
				}

				for i := 0; i < 6; i++ {
					packet.LinkLayer().LayerContents()[i] = userSuppliedNewMacAddress[i]
				}
			}

			srcMacAddressFromPacket := packet.LinkLayer().LayerContents()[6:12]
			bSrcMacAddressMatch := areByteSlicesEqual(srcMacAddressFromPacket, userSuppliedMacAddress)
			if bSrcMacAddressMatch {
				if iDebug == 1 {
					fmt.Println("There is a match on the SRC MAC Address, updating", makePrettyMacAddress(userSuppliedMacAddress), "to", makePrettyMacAddress(userSuppliedNewMacAddress))
				}

				j := 0
				for i := 6; i < 12; i++ {
					packet.LinkLayer().LayerContents()[i] = userSuppliedNewMacAddress[j]
					j++
				}
			}
		}

		makePrettyMacAddress(packet.LinkLayer().LayerContents()[0:6])
		//srcMacAddress := packet.LinkLayer().LayerContents()[6:12]

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
		log.Fatal(err)
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
