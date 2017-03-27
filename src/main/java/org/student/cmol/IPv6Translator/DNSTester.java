//package org.student.cmol.IPv6Translator;

import java.nio.ByteBuffer;

/**
 * Created by student on 27-03-17.
 */
public class DNSTester {


    DNSTester() {
        byte in_pkt[] = { /* Packet 1 */
                (byte) 0xa8, 0x12, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x04, 0x63, 0x6d, 0x6f,
                0x6c, 0x02, 0x64, 0x6b, 0x00, 0x00, 0x01, 0x00,
                0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00 };


        ByteBuffer bb_in = ByteBuffer.wrap(new byte[in_pkt.length]);

        bb_in.put(in_pkt);
        bb_in.flip();

        // Vars for reading the packet header
        ByteBuffer bb_answer;

        short dns_id   = bb_in.getShort();
        short dns_opts = bb_in.getShort();
        short dns_nQue = bb_in.getShort();
        short dns_nAns = bb_in.getShort();
        short dns_nNS  = bb_in.getShort();
        short dns_nAdd = bb_in.getShort();

        // Try to read the question section
        // Fow now, assume we only have one question
        //int bb_start = bb_in.position();
        //int bb_current = bb_start;
        //for(int i = dns_nQue; i > 0; i--) {

        int len = (bb_in.get() & 0xff);
        ByteBuffer bb_question = ByteBuffer.wrap(new byte[len]);
        byte byte_question[] = new byte[len];
        bb_in.get(byte_question);
        bb_question.put(byte_question);
        bb_question.flip();
        String qname = bb_question.toString();
        System.out.println(qname);
        short qtype = bb_in.getShort();
        short qclass = bb_in.getShort();


        // Read the answer section
        len = (bb_in.get(bb_in.position()) & 0xff);

        String rr_name;
        int new_pos;

        // Pointer to name another place
        if (len >= 192) {
            // Get position and adjust for the last two bits
            new_pos = bb_in.position() + 2;

            int pos = (bb_in.getShort() & 0x3fff);
            int nlen = (bb_in.get(pos) & 0xff);
            byte bb_rr_name[] = new byte[nlen];
            bb_in.get(bb_rr_name, pos + 1, nlen);
            rr_name = bb_rr_name.toString();
            bb_in.position(new_pos);
        }
        // Name is here
        else {
            int nlen = (bb_in.get() & 0xff);
            byte bb_rr_name[] = new byte[nlen];
            bb_in.get(bb_rr_name);
            rr_name = bb_rr_name.toString();
        }

        short rr_type   = bb_in.getShort();
        short rr_class  = bb_in.getShort();
        int   rr_ttl    = bb_in.getInt();
        int   rr_length = (bb_in.getShort() & 0xffff);

        // Wuhu, this is the actual answer
        int address[] = new int[4];
        if (rr_class == 1) { // A record, only thing that we will worry about
            address[0] = (bb_in.get() & 0xff);
            address[1] = (bb_in.get() & 0xff);
            address[2] = (bb_in.get() & 0xff);
            address[3] = (bb_in.get() & 0xff);
        }

        System.out.println(address[0]+"."+address[1]+"."+address[2]+"."+address[3]);

    }

    public static void main(String[] args) {
        DNSTester lars = new DNSTester();

    }

}
