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

/**
 * Definitions of the applications specific tags in CV-certificates.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public enum CVCTagEnum {

   // Certificate fields
   CV_CERTIFICATE         (0x7F21, true),
   CERTIFICATE_BODY       (0x7F4E, true),
   PROFILE_IDENTIFIER     (0x5F29),
   PUBLIC_KEY             (0x7F49, true),
   HOLDER_REFERENCE       (0x5F20),
   HOLDER_AUTH_TEMPLATE   (0x7F4C, true),
   EFFECTIVE_DATE         (0x5F25),
   EXPIRATION_DATE        (0x5F24),
   SIGNATURE              (0x5F37),

   OID                    (0x06),
   CA_REFERENCE           (0x42),
   REQ_AUTHENTICATION     (0x67,   true),

   // Field for Holder Authorization Template (actually, it's "Arbitrary data" according to the spec)
   ROLE_AND_ACCESS_RIGHTS (0x53),

   // Fields for Public Key
   MODULUS                (0x81),
   EXPONENT               (0x82),
   // Only for EC
   COEFFICIENT_A          (0x82),  // Note: this has the same value as EXPONENT...
   COEFFICIENT_B          (0x83),
   BASE_POINT_G           (0x84),
   BASE_POINT_R_ORDER     (0x85),
   PUBLIC_POINT_Y         (0x86),
   COFACTOR_F             (0x87),
   
   // Certificate Extensions
   CERTIFICATE_EXTENSIONS      (0x65, true),
   DISCRETIONARY_DATA_TEMPLATE (0x73, true), // each extension consists of a pair of OID and ARBITRARY_DATA
   ARBITRARY_DATA              (0x53); // same value as ROLE_AND_ACCESS_RIGHTS above

   
   private int value;
   private boolean isSequence;

   private CVCTagEnum(final int value) {
      this(value, false);
   }

   private CVCTagEnum(final int value, final boolean isSequence) {
      this.value = value;
      this.isSequence = isSequence;
   }

   /**
    * Returns the value of the tag 
    * @return
    */
   public int getValue(){
      return value;
   }

   /**
    * Returns flag indicating if this field is a Sequence
    * @return
    */
   public boolean isSequence() {
      // According to ITU-T X.690: if bit 6 in the first of two bytes 
      // is 0 then the encoding is 'primitive'.
      // Note: this doesn't work here because REQ_AUTHENTICATION has a value of 0x67!
      //return ((value >>> 8) & 0x20) != 0;
      return isSequence;
   }

}
