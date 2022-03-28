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

import org.ejbca.cvc.util.StringConverter;
import java.util.Arrays;
import java.io.Serializable;
/**
 * Represents access rights for an IS, CVCA or DVCA as specified in "BSI TR-03110-3 Advanced Security
 * Mechanisms for Machine Readable Travel Documents – Part 3 - Version 2.10".
 *
 * <p>Access can be explicitly given to DG3 (Fingerprint) and DG4 (Iris) as well as to 4 functions reserved for
 * future use (RFU).
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @author Bastian Fredriksson, PrimeKey Solutions AB
 */
public class AccessRightsIS implements AccessRights, Serializable {
   
   private static final long serialVersionUID = 1L;
	
   private static final byte READ_ACCESS_DG3 = 0x01;
   private static final byte READ_ACCESS_DG4 = 0x02;
   private static final byte READ_ACCESS_RFU1 = 0x04;
   private static final byte READ_ACCESS_RFU2 = 0x08;
   private static final byte READ_ACCESS_RFU3 = 0x10;
   private static final byte READ_ACCESS_RFU4 = 0x20;

   private byte value;

   /**
    * Create a new instance of this object from a bitmap. Only the first 6 bits representing
    * access rights are stored, the two leftmost bits are cleared if set.
    *
    * @param value a bitmap with access rights.
    */
   public AccessRightsIS(final byte value) {
      this.value = (byte) (value & 0b00111111);
   }

   public static AccessRightsIS DG3_AND_DG4() {
      return new AccessRightsIS((byte) (READ_ACCESS_DG3 | READ_ACCESS_DG4));
   }

   public static AccessRightsIS DG3() {
      return new AccessRightsIS(READ_ACCESS_DG3);
   }

   public static AccessRightsIS DG4() {
      return new AccessRightsIS(READ_ACCESS_DG4);
   }

   /**
    * Returns the access rights as a bitmap as they should appear in the certificate. Only the first 6 bits define
    * access rights.
    *
    * <p>See "BSI TR-03110-3 Advanced Security Mechanisms for Machine Readable Travel Documents – Part 3 -
    * Version 2.10, Table 20: Authorization of Inspection Systems" for details.
    *
    * @return the access rights as a bitmap.
    */
   public int getValue() {
      return value;
   }

   /**
    * Determine if this IS has read access to DG3 (Fingerprint).
    *
    * @return true iff the IS has read access to DG3.
    */
   public boolean hasDG3() {
      return (this.value & READ_ACCESS_DG3) != 0;
   }

   /**
    * Determine if this IS has read access to DG4 (Iris).
    *
    * @return true iff the IS has read access to DG4.
    */
   public boolean hasDG4() {
      return (this.value & READ_ACCESS_DG4) != 0;
   }

   private boolean hasRFU1() { return (this.value & READ_ACCESS_RFU1) != 0; }

   private boolean hasRFU2() { return (this.value & READ_ACCESS_RFU2) != 0; }

   private boolean hasRFU3() { return (this.value & READ_ACCESS_RFU3) != 0; }

   private boolean hasRFU4() { return (this.value & READ_ACCESS_RFU4) != 0; }
   
   @Override
   public byte[] getEncoded() {
       return new byte[] { value };
   }

   @Override
   public String name() {
      return "ACCESS_RIGHT_IS_" + StringConverter.byteToHex(value);
   }

   @Override
   public String toString() {
      final StringBuilder sb = new StringBuilder();
      if (hasDG3()) {
         sb.append("DG3+");
      }
      if (hasDG4()) {
         sb.append("DG4+");
      }
      if (hasRFU1()) {
         sb.append("RFU1+");
      }
      if (hasRFU2()) {
         sb.append("RFU2+");
      }
      if (hasRFU3()) {
         sb.append("RFU3+");
      }
      if (hasRFU4()) {
         sb.append("RFU4+");
      }
      return sb.length() == 0 ? "none" : sb.substring(0, sb.length() - 1);
   }

   @Override
   public boolean equals(final Object o) {
      if (o instanceof AccessRights) {
         final AccessRights other = (AccessRights) o;
         return Arrays.equals(this.getEncoded(), other.getEncoded());
      }
      return false;
   }

   @Override
   public int hashCode() {
      return Arrays.hashCode(this.getEncoded());
   }
}
