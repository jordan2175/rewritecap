// Copyright 2014-2015 Bret Jordan, All rights reserved.
//
// Use of this source code is governed by an Apache 2.0 license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"net"
	"os"
	"strings"
)

//
// -----------------------------------------------------------------------------
// replaceMacAddresses()
// -----------------------------------------------------------------------------
// Lets compare the mac address supplied with the one in the pcap file for both
// the DST MAC and SRC MAC but only if a MAC address is supplied as an ARG
// This change will be made regardless of packet type
func replaceMacAddresses(packet gopacket.Packet, userSuppliedMacAddress, userSuppliedMacAddressNew []byte) {
	dstMacAddressFromPacket := packet.LinkLayer().LayerContents()[0:6]
	srcMacAddressFromPacket := packet.LinkLayer().LayerContents()[6:12]

	bDstMacAddressMatch := areByteSlicesEqual(dstMacAddressFromPacket, userSuppliedMacAddress)
	if bDstMacAddressMatch {
		if iDebug == 1 {
			fmt.Println("DEBUG: There is a match on the DST MAC Address, updating", makePrettyMacAddress(userSuppliedMacAddress), "to", makePrettyMacAddress(userSuppliedMacAddressNew))
		}

		for i := 0; i < 6; i++ {
			packet.LinkLayer().LayerContents()[i] = userSuppliedMacAddressNew[i]
		}
	}

	bSrcMacAddressMatch := areByteSlicesEqual(srcMacAddressFromPacket, userSuppliedMacAddress)
	if bSrcMacAddressMatch {
		if iDebug == 1 {
			fmt.Println("DEBUG: There is a match on the SRC MAC Address, updating", makePrettyMacAddress(userSuppliedMacAddress), "to", makePrettyMacAddress(userSuppliedMacAddressNew))
		}

		j := 0
		for i := 6; i < 12; i++ {
			packet.LinkLayer().LayerContents()[i] = userSuppliedMacAddressNew[j]
			j++
		}
	}
} // replaceMacAddresses()

//
// -----------------------------------------------------------------------------
// parseSuppliedLayer2Address()
// -----------------------------------------------------------------------------
// Figure out if we need to change a layer 2 mac address
func parseSuppliedLayer2Address(mac string) []byte {
	userSuppliedMacAddress := make([]byte, 6, 6)

	if mac != "" {
		var err error
		userSuppliedMacAddress, err = net.ParseMAC(mac)

		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}

		if iDebug == 1 {
			fmt.Println("DEBUG: Passed in MAC Address to Change", mac)
			fmt.Println("DEBUG: Parsed MAC Address to", userSuppliedMacAddress)
		}
	}

	return userSuppliedMacAddress
} // parseSuppliedLayer2Address()

//
// -----------------------------------------------------------------------------
//  makePrettyMacAddress()
// -----------------------------------------------------------------------------
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
	if iDebug == 1 {
		fmt.Println("DEBUG: MAC Address", sNewMAC)
	}

	return sNewMAC
} // makePrettyMacAddress()
