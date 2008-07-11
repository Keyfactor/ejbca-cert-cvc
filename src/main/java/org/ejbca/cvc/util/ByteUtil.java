/*************************************************************************
 *                                                                       *
 *  CERT-CVC: EAC 1.11 Card Verifiable Certificate Library               * 
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.cvc.util;

/**
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class ByteUtil {

   /**
    * Compress the passed in byte array so that leading 0x00 and 0xff are
    * removed when possible. E.g. 
    * 0x00000453 ->>> 0x0453 
    * 0xfffffff2 ->>> 0xf2
    * 0xff192312 ->>> 0xff192312 (unchanged) 
    * 0xffff8039 ->>> 0x8039 
    * data2c is set to the compressed value.
    * 
    * @param dataLength Valid length of data in data2c.
    */
   public static byte[] reduceBytes2c(byte[] rd, int offset) {
      // look for leading zeros, if the value
      // is dataLength bytes long then look
      // at up to the first (dataLength - 1) bytes
      // to see if leading 0x00 can be removed.

      int dataLength = rd.length;
      int leading;
      for (leading = 0; leading < (dataLength - 1); leading++) {
         if (rd[offset + leading] != (byte)0)
            break;

         // if the hi bit of the next byte is set
         // then we cannot strip this 0x00 otherwise
         // the number will turn negative.
         if ((rd[offset + leading + 1] & 0x80) != 0)
            break;
      }

      if (leading == 0) {
         // now a similar trick with 0xff, but a slight
         // complication.
         for (; leading < (dataLength - 1); leading++) {
            // Need to check the highest byte of the
            // would-be remaining significant byte is
            // set to indicate this is still a negative number

            if ((rd[offset + leading] == (byte)0xff) && ((rd[offset + leading + 1] & (byte)0x80) != 0))
               continue;
            break;
         }
      }

      if ((leading != 0) || (rd.length != dataLength)) {
         byte[] reduced = new byte[dataLength - leading];
         System.arraycopy(rd, offset + leading, reduced, 0, reduced.length);
         return reduced;
      }

      return rd;
   }
}
