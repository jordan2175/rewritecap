// Copyright 2014-2017 Bret Jordan, All rights reserved.
//
// Use of this source code is governed by an Apache 2.0 license
// that can be found in the LICENSE file in the root of the source
// tree.

package layer2

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/jordan2175/rewritecap/lib/common"
	"net"
	"os"
	"strings"
)

var iDebug = 0

//
// -----------------------------------------------------------------------------
// ReplaceMacAddresses()
// -----------------------------------------------------------------------------
// Lets compare the mac address supplied with the one in the pcap file for both
// the DST MAC and SRC MAC but only if a MAC address is supplied as an ARG
// This change will be made regardless of packet type
func ReplaceMacAddresses(packet gopacket.Packet, userSuppliedMacAddress, userSuppliedMacAddressNew []byte) {
	dstMacAddressFromPacket := packet.LinkLayer().LayerContents()[0:6]
	srcMacAddressFromPacket := packet.LinkLayer().LayerContents()[6:12]

	bDstMacAddressMatch := common.AreByteSlicesEqual(dstMacAddressFromPacket, userSuppliedMacAddress)
	if bDstMacAddressMatch {
		if iDebug == 1 {
			fmt.Println("DEBUG: There is a match on the DST MAC Address, updating", MakePrettyMacAddress(userSuppliedMacAddress), "to", MakePrettyMacAddress(userSuppliedMacAddressNew))
		}

		for i := 0; i < 6; i++ {
			packet.LinkLayer().LayerContents()[i] = userSuppliedMacAddressNew[i]
		}
	}

	bSrcMacAddressMatch := common.AreByteSlicesEqual(srcMacAddressFromPacket, userSuppliedMacAddress)
	if bSrcMacAddressMatch {
		if iDebug == 1 {
			fmt.Println("DEBUG: There is a match on the SRC MAC Address, updating", MakePrettyMacAddress(userSuppliedMacAddress), "to", MakePrettyMacAddress(userSuppliedMacAddressNew))
		}

		j := 0
		for i := 6; i < 12; i++ {
			packet.LinkLayer().LayerContents()[i] = userSuppliedMacAddressNew[j]
			j++
		}
	}
} // ReplaceMacAddresses()

//
// -----------------------------------------------------------------------------
// ParseSuppliedLayer2Address()
// -----------------------------------------------------------------------------
// Figure out if we need to change a layer 2 mac address
func ParseSuppliedLayer2Address(mac string) []byte {
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
} // ParseSuppliedLayer2Address()

//
// -----------------------------------------------------------------------------
//  MakePrettyMacAddress()
// -----------------------------------------------------------------------------
// This function will create a human readable MAC address in upper case using
// the : notation between octets
func MakePrettyMacAddress(mac []byte) string {
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
} // MakePrettyMacAddress()
