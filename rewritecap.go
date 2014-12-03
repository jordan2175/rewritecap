// Copyright 2014 Bret Jordan, All rights reserved.
//

package main

import (
	"code.google.com/p/getopt"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/pcapgo"
	"fmt"
	"log"
	"os"
	"time"
)

var sPcapSrcFilename = getopt.StringLong("file", 'f', "", "Filename of the source PCAP file", "string")
var sPcapNewFilename = getopt.StringLong("newfile", 'n', "", "Filename for the new PCAP file", "string")

var iNewYear = getopt.IntLong("year", 'y', 0, "Rebase to Year (yyyy)", "int")
var iNewMonth = getopt.IntLong("month", 'm', 0, "Rebase to Month (mm)", "int")
var iNewDay = getopt.IntLong("day", 'd', 0, "Rebase to Day (dd)", "int")

var bOptHelp = getopt.BoolLong("help", 0, "Help")
var bOptVer = getopt.BoolLong("version", 0, "Version")

var iCounter = 0
var iDebug = 0
var sVersion = "1.00"

func main() {
	getopt.Parse()

	if *bOptVer {
		fmt.Println("Version:", sVersion)
		os.Exit(0)
	}

	getopt.HelpColumn = 25
	if *bOptHelp || (*sPcapSrcFilename == "" || *sPcapNewFilename == "") {
		getopt.Usage()
		os.Exit(0)
	}

	// Figure out if there is a change needed for the date of each packet.  We will
	// compute the difference between what is in the first packet and what was passed
	// in via the command line arguments.
	iDiffYear := 0
	iDiffMonth := 0
	iDiffDay := 0

	pcapStartTimestamp := getFirstPacketTimestamp(*sPcapSrcFilename)

	if *iNewYear != 0 {
		iDiffYear = *iNewYear - pcapStartTimestamp.Year()
	}
	if *iNewMonth != 0 {
		iDiffMonth = *iNewMonth - int(pcapStartTimestamp.Month())
	}
	if *iNewDay != 0 {
		iDiffDay = *iNewDay - pcapStartTimestamp.Day()
	}

	if iDebug == 1 {
		fmt.Println("DEBUG: Y/M/D deltas", iDiffYear, iDiffMonth, iDiffDay)
	}
	// End compute date change

	// Get a handle to the PCAP source file so we can loop through each packet and make
	// changes as needed.
	handle, err1 := pcap.OpenOffline(*sPcapSrcFilename)
	if err1 != nil {
		log.Fatal(err1)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Create file handle to write to
	fileHandle, err2 := os.Create(*sPcapNewFilename)
	if err2 != nil {
		log.Fatal(err2)
	}
	writer := pcapgo.NewWriter(fileHandle)
	writer.WriteFileHeader(65535, handle.LinkType())

	fmt.Println("Each '.' represents 1000 packets converted.")

	// Loop through every packet and update them as needed writing the changes out to a new file
	for packet := range packetSource.Packets() {
		if iDebug == 1 {
			fmt.Println("DEBUG: ", "----------------------------------------")
		}

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
	}
	fileHandle.Close()
	fmt.Println("\nNumber of packets processed:", iCounter)

} // main()

// We need to open the pcap file and read the timestamp from the first packet so that we can figure
// out an offset for all future packets.  This will address the problem of the pcap spanning multiple
// days, months, years  as we will always add the same amount of offset to each packet.
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
