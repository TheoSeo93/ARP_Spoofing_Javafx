package model;

import java.util.Arrays;
/*
 * ARP: The protocol that determines MAC address with IP address
 */
public class ARP {
	// 6 bytes
	private byte[] destinationMac = new byte[6];
	private byte[] sourceMac = new byte[6];
	private byte[] ethernetType = { 0x08, 0x06 }; // ARP
	private byte[] hardwareType = { 0x00, 0x01 }; // Ethernet
	private byte[] protocolType = { 0x08, 0x00 }; // IPv4
	private byte hardwareSize = 0x06; 	 // MAC Size 6 bytes
	private byte protocolSize = 0x04;	 // IP Size  4 bytes
	private byte[] opcode = new byte[2]; // Request : 0001 Reply: 0002
	private byte[] senderMAC = new byte[6];
	private byte[] senderIP = new byte[4];
	private byte[] targetMAC = new byte[6];
	private byte[] targetIP = new byte[4];
	
	/*
	 * Makes an ARP request packet in order to target MAC address
	 * I know IP address of the targetIP, so I am going to request with it
	 */
	public void makeARPRequest(byte[] sourceMAC, byte[] senderIP, byte[] targetIP) {
		// Broadcast Request : 0xff
		// Since I don't know the target MAC address, I make a request to everyone
		Arrays.fill(destinationMac, (byte) 0xff);
		//Fill in the sourceMAC
		System.arraycopy(sourceMAC, 0, this.sourceMac, 0, 6);
		opcode[0] = 0x00;
		opcode[1] = 0x01; // Request:0001
		//ARP request: source MAC and senderMAC should match each other.
		System.arraycopy(sourceMAC, 0, this.senderMAC, 0, 6);
		System.arraycopy(senderIP, 0, this.senderIP, 0, 4);
		//I don't know the target MAC yet, so I fill in 00
		Arrays.fill(targetMAC, (byte) 0x00);
		System.arraycopy(targetIP, 0, this.targetIP, 0, 4);
	}
	
	public void makeARPReply(byte[] destinationMAC, byte[] sourceMAC, byte[] senderMAC, byte[] senderIP,
			byte[] targetIP, byte[] targetMAC) {
		System.arraycopy(destinationMAC, 0, this.destinationMac, 0, 6);
		System.arraycopy(sourceMac, 0, this.sourceMac, 0, 6);
		opcode[0] = 0x00;
		opcode[1] = 0x02;	//Reply: 0002
		System.arraycopy(senderMAC, 0, this.senderMAC, 0, 6);
		System.arraycopy(destinationMAC, 0, this.destinationMac, 0, 6);
		System.arraycopy(senderIP, 0, this.senderIP, 0, 4);
		System.arraycopy(targetMAC, 0, this.targetMAC, 0, 6);
		System.arraycopy(targetIP, 0, this.targetIP, 0, 4);
	}
	/*
	 * Packet into array of bytes (42 bytes) 
	 */
	public byte[] getPacket() {
		// ARP packet = 42 bytes
		byte[] bytes = new byte[42];
		System.arraycopy(destinationMac, 0, bytes, 0, destinationMac.length);
		System.arraycopy(sourceMac, 0, bytes, 6, sourceMac.length);
		System.arraycopy(ethernetType, 0, bytes, 12, ethernetType.length);
		System.arraycopy(hardwareType, 0, bytes, 14, hardwareType.length);
		System.arraycopy(protocolType, 0, bytes, 16, protocolType.length);
		bytes[18] = hardwareSize;
		bytes[19] = protocolSize;
		System.arraycopy(opcode, 0, bytes, 20, opcode.length);
		System.arraycopy(senderMAC, 0, bytes, 22, senderMAC.length);
		System.arraycopy(senderIP, 0, bytes, 28, senderIP.length);
		System.arraycopy(targetMAC, 0, bytes, 32, targetMAC.length);
		System.arraycopy(targetIP, 0, bytes, 38, targetIP.length);
		return bytes;

	}
}
