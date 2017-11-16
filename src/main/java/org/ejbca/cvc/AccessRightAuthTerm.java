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
package org.ejbca.cvc;

import java.io.Serializable;

import org.ejbca.cvc.util.StringConverter;


/**
 * Represents Access Rights for Inspection Systems.
 * Use with OID CVCObjectIdentifiers.id_EAC_AT.
 * Described in the EAC 2.1 spec part 3 page 69.
 * 
 * @author Samuel Lidén Borell, PrimeKey Solutions AB
 * @version $Id$
 *
 */
public class AccessRightAuthTerm implements AccessRights, Serializable {

   private static final long serialVersionUID = 1L;

   private static final int MAX_BIT = 37;

   // Write access
   public static final int BIT_WRITE_DG17 = 37;
   public static final int BIT_WRITE_DG18 = 36;
   public static final int BIT_WRITE_DG19 = 35;
   public static final int BIT_WRITE_DG20 = 34;
   public static final int BIT_WRITE_DG21 = 33;

   // Read access
   public static final int BIT_READ_DG21 = 28;
   public static final int BIT_READ_DG20 = 27;
   public static final int BIT_READ_DG19 = 26;
   public static final int BIT_READ_DG18 = 25;
   public static final int BIT_READ_DG17 = 24;
   public static final int BIT_READ_DG16 = 23;
   public static final int BIT_READ_DG15 = 22;
   public static final int BIT_READ_DG14 = 21;
   public static final int BIT_READ_DG13 = 20;
   public static final int BIT_READ_DG12 = 19;
   public static final int BIT_READ_DG11 = 18;
   public static final int BIT_READ_DG10 = 17;
   public static final int BIT_READ_DG9 = 16;
   public static final int BIT_READ_DG8 = 15;
   public static final int BIT_READ_DG7 = 14;
   public static final int BIT_READ_DG6 = 13;
   public static final int BIT_READ_DG5 = 12;
   public static final int BIT_READ_DG4 = 11;
   public static final int BIT_READ_DG3 = 10;
   public static final int BIT_READ_DG2 =  9;
   public static final int BIT_READ_DG1 =  8;

   // Special functions
   public static final int BIT_INSTALL_QUALIFIED_CERT = 7;
   public static final int BIT_INSTALL_CERT = 6;
   public static final int BIT_PIN_MANAGEMENT = 5;
   public static final int BIT_CAN_ALLOWED = 4;
   public static final int BIT_PRIVILEGED_TERMINAL = 3;
   public static final int BIT_RESTRICTED_IDENTIFICATION = 2;
   public static final int BIT_COMMUNITY_ID_VERIFICATION = 1;
   public static final int BIT_AGE_VERIFICATION = 0;


   private final byte[] bytes;

   public AccessRightAuthTerm() {
      this.bytes = new byte[5];
   }

   public AccessRightAuthTerm(byte[] bytes) {
      if (bytes.length != 5) {
         throw new IllegalArgumentException("byte array length must be 5, was "+bytes.length);
      }
      this.bytes = bytes.clone();
      this.bytes[0] &= ~0xC0; // Clear role bits
   }


   public boolean getFlag(int bitNumber) {
      if (bitNumber < 0 || bitNumber > MAX_BIT) {
         throw new ArrayIndexOutOfBoundsException(bitNumber);
      }
      int byteindex = bytes.length - 1 - (bitNumber>>3);
      int bit = (bytes[byteindex] >> (bitNumber & 0x7)) & 1;
      return bit == 1;
   }

   public void setFlag(int bitNumber, boolean state) {
      if (bitNumber < 0 || bitNumber > MAX_BIT) {
         throw new ArrayIndexOutOfBoundsException(bitNumber);
      }
      int byteindex = bytes.length - 1 - (bitNumber>>3);
      int bit = 1 << (bitNumber & 0x7);
      bytes[byteindex] &= ~bit; // clear bit
      bytes[byteindex] |= state ? bit : 0; // set bit
   }


   @Override
   public byte[] getEncoded() {
       return bytes.clone();
   }

   @Override
   public String toString() {
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i <= MAX_BIT; i++) {
         if (getFlag(i)) {
            sb.append(flagToString(i));
            sb.append(", ");
         }
      }
      if (sb.length() > 0) {
         sb.delete(sb.length()-2, sb.length());
      }
      return sb.toString();
   }

   private static String flagToString(int flag) {
      if (flag < 0 || flag > MAX_BIT) { throw new ArrayIndexOutOfBoundsException(flag); }
      // Data groups
      if (flag >= BIT_WRITE_DG21) { return "W-DG"+(21+BIT_WRITE_DG21-flag); }
      if (flag > BIT_READ_DG21) { return "RFU-"+flag; } // reserved for future use
      if (flag >= BIT_READ_DG1) { return "R-DG"+(flag-BIT_READ_DG1+1); }
      // Special functions
      switch (flag) {
      case BIT_INSTALL_QUALIFIED_CERT: return "Install Qualified Certificate";
      case BIT_INSTALL_CERT: return "Install Certificate";
      case BIT_PIN_MANAGEMENT: return "PIN Management";
      case BIT_CAN_ALLOWED: return "CAN Allowed";
      case BIT_PRIVILEGED_TERMINAL: return "Privileged Terminal";
      case BIT_RESTRICTED_IDENTIFICATION: return "Restricted Identification";
      case BIT_COMMUNITY_ID_VERIFICATION: return "Community ID Verification";
      case BIT_AGE_VERIFICATION: return "Age Verification";
      default: throw new IllegalStateException();
      }
   }

   @Override
   public String name() {
      return "ACCESS_RIGHT_AT_"+StringConverter.byteToHex(bytes);
   }

}
