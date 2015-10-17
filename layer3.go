// Copyright 2014-2015 Bret Jordan, All rights reserved.
//
// Use of this source code is governed by an Apache 2.0 license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"fmt"
	"github.com/google/gopacket"
	"net"
)

//
// -----------------------------------------------------------------------------
// replaceIPv4Addresses()
// -----------------------------------------------------------------------------
func replaceIPv4Addresses(packet gopacket.Packet, i802dot1QOffset int, userSuppliedIPv4Address, userSuppliedIPv4AddressNew []byte) {
	iEthType1 := 12 + i802dot1QOffset
	iEthType2 := 13 + i802dot1QOffset

	// Make sure the eth.type is 0800 and the IP type and size is 0x45 for IPv4
	if packet.LinkLayer().LayerContents()[iEthType1] == 8 && packet.LinkLayer().LayerContents()[iEthType2] == 0 && packet.NetworkLayer().LayerContents()[0] == 69 {

		// Define the byte offsets for the data we are looking for
		iLayer3SrcIPStart := 12 + i802dot1QOffset
		iLayer3SrcIPEnd := iLayer3SrcIPStart + 4
		iLayer3DstIPStart := 16 + i802dot1QOffset
		iLayer3DstIPEnd := iLayer3DstIPStart + 4

		srcIPv4AddressFromPacket := packet.NetworkLayer().LayerContents()[iLayer3SrcIPStart:iLayer3SrcIPEnd]
		dstIPv4AddressFromPacket := packet.NetworkLayer().LayerContents()[iLayer3DstIPStart:iLayer3DstIPEnd]

		// Update SRC IP address
		bSrcIPv4AddressMatch := areByteSlicesEqual(srcIPv4AddressFromPacket, userSuppliedIPv4Address)
		if bSrcIPv4AddressMatch {
			if iDebug == 1 {
				fmt.Println("DEBUG: There is a match on the SRC IPv4 Address, updating", userSuppliedIPv4Address, "to", userSuppliedIPv4AddressNew)
			}
			j := 0
			for i := iLayer3SrcIPStart; i < iLayer3SrcIPEnd; i++ {
				packet.NetworkLayer().LayerContents()[i] = userSuppliedIPv4AddressNew[j]
				j++
			}
		}

		// Update DST IP address
		bDstIPv4AddressMatch := areByteSlicesEqual(dstIPv4AddressFromPacket, userSuppliedIPv4Address)
		if bDstIPv4AddressMatch {
			if iDebug == 1 {
				fmt.Println("DEBUG: There is a match on the DST IPv4 Address, updating", userSuppliedIPv4Address, "to", userSuppliedIPv4AddressNew)
			}
			j := 0
			for i := iLayer3DstIPStart; i < iLayer3DstIPEnd; i++ {
				packet.NetworkLayer().LayerContents()[i] = userSuppliedIPv4AddressNew[j]
				j++
			}
		}
	}
} // replaceIPv4Addresses()

//
// -----------------------------------------------------------------------------
// parseSuppliedLayer3IPv4Addresses()
// -----------------------------------------------------------------------------
// Figure out if we need to change a layer 3 IPv4 address
func parseSuppliedLayer3IPv4Address(address string) []byte {
	userSuppliedIPv4Address := make([]byte, 4, 4)

	// Since ParseIP returns a 16 byte slice (aka 128 bit address to accomodate IPv6)
	// just grab what we need
	if address != "" {
		userSuppliedIPv4Address = net.ParseIP(address)[12:16]

		if iDebug == 1 {
			fmt.Println("DEBUG: Passed in IPv4 Address to Change", address)
			fmt.Println("DEBUG: Parsed IPv4 Address to", userSuppliedIPv4Address)
		}
	}

	return userSuppliedIPv4Address
} // parseSuppliedLayer3IPv4Addresses()
