//package org.student.cmol.IPv6Translator;

import java.nio.ByteBuffer;

/**
 * Created by student on 27-03-17.
 */



public class DNSTester {

  private static byte[] PREFIX = {
    0x20, 0x01, 0x0D, (byte) 0xB8,(byte) 0xAC,
    (byte) 0x10, (byte) 0xFE, 0x01};

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
          System.out.print(blob+" ");
        }
        System.out.println();
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

    System.out.println(bytesToHex(bb_in.array()));
    System.out.println(bytesToHex(new_pkt.array()));

    System.out.println("Old size: "+bb_in.limit()+" New size: "+new_pkt.limit());

  }



  public static String bytesToHex(byte[] in) {
    final StringBuilder builder = new StringBuilder();
    for(byte b : in) {
      builder.append(String.format("%02x", b));
    }
    return builder.toString();
  }



  public static void main(String[] args) {
    DNSTester lars = new DNSTester();

    System.out.println(hex2dec(dec2hex(0)));

  }

}
