//package org.student.cmol.IPv6Translator;

import java.nio.ByteBuffer;

/**
 * Created by student on 27-03-17.
 */
public class DNSTester {


    DNSTester() {
        byte in_pkt[] = { /* Packet 4 */
                (byte) 0xae, 0x1b, (byte) 0x81, (byte) 0x80, 0x00, 0x01, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x01, 0x04, 0x63, 0x6d, 0x6f,
                0x6c, 0x02, 0x64, 0x6b, 0x00, 0x00, 0x01, 0x00,
                0x01, (byte) 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x1b, 0x47, 0x00, 0x04, 0x5d, 0x5a, 0x72,
                0x37, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00 };

        byte in_pkt2[] = { /* Packet 4 */
                0x28, (byte) 0xbe, (byte) 0x81, (byte) 0x80, 0x00, 0x01, 0x00, 0x04,
                0x00, 0x00, 0x00, 0x01, 0x02, 0x6d, 0x78, 0x06,
                0x66, 0x61, 0x62, 0x2d, 0x69, 0x74, 0x02, 0x64,
                0x6b, 0x00, 0x00, 0x01, 0x00, 0x01, (byte) 0xc0, 0x0c,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x68,
                0x00, 0x04, 0x5d, 0x5a, 0x74, 0x02, (byte) 0xc0, 0x0c,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x68,
                0x00, 0x04, 0x5d, 0x5a, 0x73, 0x02, (byte) 0xc0, 0x0c,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x68,
                0x00, 0x04, 0x5d, 0x5a, 0x74, (byte) 0xfe, (byte) 0xc0, 0x0c,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x68,
                0x00, 0x04, 0x5d, 0x5a, 0x73, (byte) 0xfe, 0x00, 0x00,
                0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00 };


        ByteBuffer bb_in = ByteBuffer.wrap(new byte[in_pkt2.length]);

        bb_in.put(in_pkt2);
        bb_in.flip();

        // We don't strictly need all of these, but for now they are nice
        short dns_id   = bb_in.getShort();
        short dns_opts = bb_in.getShort();
        int dns_nQue   = (bb_in.getShort() & 0xff);
        int dns_nAns   = (bb_in.getShort() & 0xff);
        int dns_nNS    = (bb_in.getShort() & 0xff);
        int dns_nAdd   = (bb_in.getShort() & 0xff);

        // Try to read the question section
        // Forget about trying to read the name, just skip the thing..
        for (int i = 0; i < dns_nQue; i++) {
          while(true) {
              int len = (bb_in.get() & 0xff);
              //System.out.println(len);
              if(len == 0) {break;}
              else {
                  bb_in.position(bb_in.position() + len);
              }
          }
          short qtype = bb_in.getShort();
          short qclass = bb_in.getShort();
        }


        // Read the answer section
        for (int i = 0; i < dns_nAns; i++) {
          int start = bb_in.position();
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

          // Read the record type
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
          int end = bb_in.position();
          System.out.println("Data range: "+start+"-"+end+"   "+address[0]+"."+address[1]+"."+address[2]+"."+address[3]);
        }

    }

    public static void main(String[] args) {
        DNSTester lars = new DNSTester();

    }

}
