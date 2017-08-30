// Copyright 2014-2017 Bret Jordan, All rights reserved.
//
// Use of this source code is governed by an Apache 2.0 license
// that can be found in the LICENSE file in the root of the source
// tree.

package arp

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/jordan2175/rewritecap/lib/common"
	"github.com/jordan2175/rewritecap/lib/layer2"
)

var iDebug = 0

//
// -----------------------------------------------------------------------------
// ReplaceArpPayloadMacAddresses()
// -----------------------------------------------------------------------------
// Lets compare the mac address supplied with the one in the ARP packet for both
// the SRC MAC and TARGET MAC in the ARP Payload
func ReplaceArpPayloadMacAddresses(packet gopacket.Packet, i802dot1QOffset int, userSuppliedMacAddress, userSuppliedMacAddressNew []byte) {
	// Define the byte offsets for the data we are looking for
	iArpSenderMacStart := 8 + i802dot1QOffset
	iArpSenderMacEnd := iArpSenderMacStart + 6
	iArpTargetMacStart := 18 + i802dot1QOffset
	iArpTargetMacEnd := iArpTargetMacStart + 6

	senderMacAddressFromArpPacket := packet.LinkLayer().LayerPayload()[iArpSenderMacStart:iArpSenderMacEnd]
	targetMacAddressFromArpPacket := packet.LinkLayer().LayerPayload()[iArpTargetMacStart:iArpTargetMacEnd]

	// Sender MAC in payload
	bSenderMacAddressMatch := common.AreByteSlicesEqual(senderMacAddressFromArpPacket, userSuppliedMacAddress)
	if bSenderMacAddressMatch {
		if iDebug == 1 {
			fmt.Println("DEBUG: There is a match on the ARP Sender MAC Address, updating", layer2.MakePrettyMacAddress(userSuppliedMacAddress), "to", layer2.MakePrettyMacAddress(userSuppliedMacAddressNew))
		}

		j := 0
		for i := iArpSenderMacStart; i < iArpSenderMacEnd; i++ {
			packet.LinkLayer().LayerPayload()[i] = userSuppliedMacAddressNew[j]
			j++
		}
	}

	// Target MAC in payload
	bTargetMacAddressMatch := common.AreByteSlicesEqual(targetMacAddressFromArpPacket, userSuppliedMacAddress)
	if bTargetMacAddressMatch {
		if iDebug == 1 {
			fmt.Println("DEBUG: There is a match on the ARP Target MAC Address, updating", layer2.MakePrettyMacAddress(userSuppliedMacAddress), "to", layer2.MakePrettyMacAddress(userSuppliedMacAddressNew))
		}

		j := 0
		for i := iArpTargetMacStart; i < iArpTargetMacEnd; i++ {
			packet.LinkLayer().LayerPayload()[i] = userSuppliedMacAddressNew[j]
			j++
		}
	}
} // ReplaceArpPayloadMacAddresses()

//
// -----------------------------------------------------------------------------
// ReplaceArpPayloadIPv4Addresses()
// -----------------------------------------------------------------------------
// Lets compare the IPv4 address supplied with the one in the ARP packet for both
// the SRC IP and TARGET IP in the ARP Payload
func ReplaceArpPayloadIPv4Addresses(packet gopacket.Packet, i802dot1QOffset int, userSuppliedIPv4Address, userSuppliedIPv4AddressNew []byte) {
	// Make sure the apr.proto.type is 0800
	if packet.LinkLayer().LayerPayload()[2] == 8 && packet.LinkLayer().LayerPayload()[3] == 0 {
		if iDebug == 1 {
			fmt.Println("DEBUG: Found an ARP packet with proto type IP")
		}
		// Define the byte offsets for the data we are looking for
		iArpSenderIPStart := 14 + i802dot1QOffset
		iArpSenderIPEnd := iArpSenderIPStart + 4
		iArpTargetIPStart := 24 + i802dot1QOffset
		iArpTargetIPEnd := iArpTargetIPStart + 4

		senderIPv4AddressFromArpPacket := packet.LinkLayer().LayerPayload()[iArpSenderIPStart:iArpSenderIPEnd]
		targetIPv4AddressFromArpPacket := packet.LinkLayer().LayerPayload()[iArpTargetIPStart:iArpTargetIPEnd]

		bSenderIPv4AddressMatch := common.AreByteSlicesEqual(senderIPv4AddressFromArpPacket, userSuppliedIPv4Address)
		if bSenderIPv4AddressMatch {
			if iDebug == 1 {
				fmt.Println("DEBUG: There is a match on the ARP Sender IPv4 Address, updating", userSuppliedIPv4Address, "to", userSuppliedIPv4AddressNew)
			}
			j := 0
			for i := iArpSenderIPStart; i < iArpSenderIPEnd; i++ {
				packet.LinkLayer().LayerPayload()[i] = userSuppliedIPv4AddressNew[j]
				j++
			}
		}

		bTargetIPv4AddressMatch := common.AreByteSlicesEqual(targetIPv4AddressFromArpPacket, userSuppliedIPv4Address)
		if bTargetIPv4AddressMatch {
			if iDebug == 1 {
				fmt.Println("DEBUG: There is a match on the ARP Target IPv4 Address, updating", userSuppliedIPv4Address, "to", userSuppliedIPv4AddressNew)
			}
			j := 0
			for i := iArpTargetIPStart; i < iArpTargetIPEnd; i++ {
				packet.LinkLayer().LayerPayload()[i] = userSuppliedIPv4AddressNew[j]
				j++
			}
		}
	}
} // ReplaceArpPayloadIPv4Addresses()
