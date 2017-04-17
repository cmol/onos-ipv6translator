/*
 * Copyright 2017 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.student.cmol.IPv6Translator;

import org.apache.felix.scr.annotations.*;
import org.onlab.packet.*;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    // Translation prefix, must be prefix owned by provider
    private static byte[] PREFIX = {
            0x20, 0x01, 0x0D, (byte) 0xB8,(byte) 0xAC,
            (byte) 0x10, (byte) 0xFE, 0x01};

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;
    private final Logger log = LoggerFactory.getLogger(getClass());
    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    @Activate
    protected void activate() {
        log.info("Started");
        packetService.addProcessor(processor,PacketProcessor.director(2));
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        processor = null;
        log.info("Stopped");
    }

    private class ReactivePacketProcessor implements PacketProcessor{

        @Override
        public void process(PacketContext packetContext) {
            InboundPacket packet = packetContext.inPacket();
            Ethernet ethPkt = packet.parsed();
            if (ethPkt == null) return;

            log.info("Packet received");
            log.info("Type: "+ethPkt.getEtherType());
            log.info("From :"+ethPkt.getSourceMAC().toString());
            log.info("To: "+ethPkt.getDestinationMAC().toString());

            IPv6 ipv6_packet;

            if(ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                // We need to translate the packet here then.
                ipv6_packet = (IPv6) (IPacket) ipv4toipv6(ethPkt);
            }
            else {
                // Ok, carry on
                ipv6_packet = (IPv6) (IPacket) ethPkt;
            }

            if (ipv6_packet.getNextHeader() == IPv6.PROTOCOL_UDP) {
                // We need to check if we are working with DNS
                UDP udp_packet = (UDP) ipv6_packet.getPayload();
                if (udp_packet.getDestinationPort() == 53) {
                    // We will assume that we are working with DNS as the destionation is port 53
                    udp_packet = transformDNS(udp_packet);
                }
                ipv6_packet.setPayload(udp_packet);
            }

            ethPkt.setPayload(ipv6_packet);
        }
    }

    private UDP transformDNS(UDP udp_packet) {
        // Disassemble data packet for translation
        byte packet[] = udp_packet.serialize();
        byte dns_packet[] = new byte[udp_packet.getLength() - 8];
        System.arraycopy(packet, 8, dns_packet, 0, dns_packet.length);

        byte rewritten[] = rewriteDNS(dns_packet);

        // Assemble new packet
        byte new_packet[] = new byte[rewritten.length + 8];
        System.arraycopy(rewritten, 0, new_packet, 8, rewritten.length);
        new_packet[0] = (byte) ((udp_packet.getSourcePort()      << 8) & 0xff); // SRC port
        new_packet[1] = (byte) ((udp_packet.getSourcePort()          ) & 0xff); // SRC port
        new_packet[2] = (byte) ((udp_packet.getDestinationPort() << 8) & 0xff); // DST port
        new_packet[3] = (byte) ((udp_packet.getDestinationPort()     ) & 0xff); // DST port
        new_packet[4] = (byte) (((rewritten.length + 8)         << 8) & 0xff); // PKT length
        new_packet[5] = (byte) (((rewritten.length + 8)             ) & 0xff); // PKT length
        new_packet[6] = 0; // Checksum
        new_packet[7] = 0; // Checksum

        // Construct packet and recalculate checksum
        UDP udp = new UDP();
        udp.deserialize(new_packet,0,new_packet.length);
        udp.resetChecksum();
        udp.serialize();

        return udp;
    }

    private Ethernet ipv4toipv6(Ethernet ethPkt) {
        IPv4 ipv4 = (IPv4) ethPkt.getPayload();
        IPv6 ipv6 = new IPv6();
        int src_addr = ipv4.getSourceAddress();
        int dst_addr = ipv4.getDestinationAddress();

        ipv6.setPayload(ipv4.getPayload());
        ipv6.setSourceAddress(address4to6(src_addr));
        ipv6.setDestinationAddress(address4to6(dst_addr));

        Ethernet packet;
        packet = (Ethernet) ethPkt.clone();
        packet.setPayload(ipv6);

        return packet;
    }

    private byte[] rewriteDNS(byte[] payload) {
        return new byte[1];
    }

    /* ********** Helper methods to make life easier by reuisng code ********** */

    // Converts a value from decimal to hex as from 192 (dec) to 0x192 (hex)
    private static int dec2hex(int dec) {
        if (dec > 255 || dec < 0) {
            throw new IllegalArgumentException("Value must be between 0 and 255");
        }
        return (dec / 100) * 256 + ((dec % 100) / 10) * 16 + dec % 100 % 10;
    }

    // Converts a value from hex to decimal as from 0x192 (hex) to 192 (dec)
    private static int hex2dec(int hex) {
        if (hex > 0x255 || hex < 0) {
            throw new IllegalArgumentException("Value must be between 0 and 0x255 (597)");
        }
        return (hex / 256) * 100 + ((hex % 256) / 16) * 10 + hex % 256 % 16;
    }

    // Take an ipv4 address as an int, and translate to ipv6 byte[]
    private static byte[] address4to6(int addr) {
        byte v4arr[] = new byte[4];
        byte v6arr[] = new byte[16];

        // Extract bytes of v4 address
        v4arr[0] = (byte) ((addr >> 24) & 0xff);
        v4arr[1] = (byte) ((addr >> 16) & 0xff);
        v4arr[2] = (byte) ((addr >> 8 ) & 0xff);
        v4arr[3] = (byte) ( addr        & 0xff);

        // Copy in translation prefix
        System.arraycopy(PREFIX,0,v6arr,0,8);

        // Translate the single entities and add them to the new v6addr array
        for( int i = 0; i < 4; i++) {
            int translated = dec2hex((int) v4arr[i]);
            v6arr[8+i*2]   = (byte) ((translated >> 8) & 0xff);
            v6arr[8+i*2+1] = (byte) ( translated       & 0xff);
        }

        return v6arr;
    }

    // Take an ipv6 address as a byte[], and translate to ipv4 byte[]
    private static byte[] address6to4(byte[] addr) {
        byte v4arr[] = new byte[4];
        int v6arr[]  = new int[4];

        // Extract shorts (to ints) of v6 address
        v6arr[0] = ((addr[8]  << 8) & (addr[9]));
        v6arr[1] = ((addr[10] << 8) & (addr[11]));
        v6arr[2] = ((addr[12] << 8) & (addr[13]));
        v6arr[3] = ((addr[14] << 8) & (addr[15]));

        // Translate the single entities and add them to the new v4addr array
        for( int i = 0; i < 4; i++) {
            v4arr[i] = (byte) ( hex2dec(v6arr[i]) & 0xff);
        }

        return v4arr;
    }



}
