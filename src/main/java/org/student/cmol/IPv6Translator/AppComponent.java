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

import java.nio.ByteBuffer;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    // Translation prefix, must be prefix owned by provider (2001:0db8:ac10:fe01::)
    private static byte[] V6_TRANSLATION_PREFIX = {
            0x20, 0x01, 0x0D, (byte) 0xB8,(byte) 0xAC,
            (byte) 0x10, (byte) 0xFE, 0x01};

    // Prefix for direct access to machines owned by provider (2001:0db8:ac10:feff::)
    private static byte[] V6_DIRECT_PREFIX = {
            0x20, 0x01, 0x0D, (byte) 0xB8,(byte) 0xAC,
            (byte) 0x10, (byte) 0xFE, (byte) 0xff};

    // IPv4 addresses owned by provider
    private static int V4_NET     = 0x0a000000; //10 .  0.  0.0
    private static int V4_NETMASK = 0xffffff00; //255.255.255.0

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
        ByteBuffer bb_in = ByteBuffer.wrap(new byte[payload.length]);

        bb_in.put(payload);
        bb_in.flip();

        // We don't strictly need all of these, but for now they are nice
        short dns_id   = bb_in.getShort();
        short dns_opts = bb_in.getShort();
        int dns_nQue   = (bb_in.getShort() & 0xff);
        int dns_nAns   = (bb_in.getShort() & 0xff);
        int dns_nNS    = (bb_in.getShort() & 0xff);
        int dns_nAdd   = (bb_in.getShort() & 0xff);

        // Try to read the questions section
        // Forget about trying to read the name, just skip the thing..
        for (int i = 0; i < dns_nQue; i++) {
            while(true) {
                int len = (bb_in.get() & 0xff);
                if(len == 0) {break;}
                else {
                    bb_in.position(bb_in.position() + len);
                }
            }
            short qtype = bb_in.getShort();
            short qclass = bb_in.getShort();
        }


        // Read the answer section
        int answers_start_position = bb_in.position();

        // It is at this time hard to know how large of a buffer we need,
        // so a conservative estimate of dns_nAns * current size is used.
        ByteBuffer answers = ByteBuffer.wrap(new byte[bb_in.limit() * dns_nAns]);

        // Loop over all the answers
        for (int i = 0; i < dns_nAns; i++) {
            int answer_start = bb_in.position();

            // Get name pos/lenght
            int len = (bb_in.get(bb_in.position()) & 0xff);

            // Pointer to name another place
            if (len >= 192) {
                // Just skip ahead two octets
                bb_in.position(bb_in.position() + 2);
            }
            // Name is here
            else {
                // Skip the damn name..
                bb_in.position(bb_in.position() + len);
                while(true) {
                    len = (bb_in.get() & 0xff);
                    if(len == 0) {break;}
                    else {
                        bb_in.position(bb_in.position() + len);
                    }
                }

            }

            // Record where the name ends so we can just copy over the bytes
            int name_end = bb_in.position();

            // Read the record type
            short rr_type   = bb_in.getShort();
            short rr_class  = bb_in.getShort();
            int   rr_ttl    = bb_in.getInt();
            int   rr_length = (bb_in.getShort() & 0xffff);

            // Record the meta data end
            int meta_end = bb_in.position();

            // Copy in the whole RR, we don't need to edit it as it is not an
            // A record type RR
            if(rr_type != 1) {
                // Read the whole RR and put it in an answer buffer
                bb_in.position(answer_start);
                byte buffer[] = new byte[meta_end - answer_start + rr_length];
                bb_in.get(buffer);
                answers.put(buffer);

                // Advance the input buffer by the payload length
                bb_in.position(meta_end + rr_length);
            }
            // A record, only thing that we will worry about
            else {
                // Copy the name from before (rewind pos, copy, ff pos)
                bb_in.position(answer_start);
                byte name_buffer[] = new byte[name_end - answer_start];
                bb_in.get(name_buffer);
                answers.put(name_buffer);
                bb_in.position(meta_end);

                // Set type, class, ttl and length of answer
                answers.putShort((short) 28); // AAAA type RR
                answers.putShort(rr_class);
                answers.putInt(rr_ttl);
                answers.putShort((short) 16); // Length of IPv6 address in bytes

                // Get the prefix into the buffer as start of the answer
                answers.put(PREFIX);

                // Read IPv4 address and translate to IPv6 (4 -> 8 bytes)
                for (int j = 0; j < 4 ; j++ ) {
                    int octet = bb_in.get() & 0xff;
                    int blob  = dec2hex(octet);
                    answers.put((byte) ((blob & 0xff00) >> 8));
                    answers.put((byte) (blob & 0xff));
                }
            }

        } // Read answers end

        // Finalize the answer buffer
        answers.flip();
        int ns_start_pos = bb_in.position();

        // Create new buffer with the new DNS packet
        ByteBuffer new_pkt = ByteBuffer.wrap(new byte[
                answers_start_position + answers.limit() +
                        bb_in.limit() - bb_in.position()]);

        // Add the header
        byte header[] = new byte[answers_start_position];
        bb_in.position(0);
        bb_in.get(header);
        new_pkt.put(header);

        // Add the answers
        new_pkt.put(answers);

        // Add the NS and additional fields
        bb_in.position(ns_start_pos);
        new_pkt.put(bb_in);

        // Finalize the packet
        new_pkt.flip();

        return new_pkt.array();
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
