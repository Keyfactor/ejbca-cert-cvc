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
 * Definition av de applikationsspecifika taggarna i ett CV-certifikat.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public enum CVCTagEnum {

   // Certifikatf�lt
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

   // Holder Authorization Template-f�lt
   ROLE_AND_ACCESS_RIGHTS (0x53),

   // Public Key-f�lt
   MODULUS                (0x81),
   EXPONENT               (0x82),
   // Endast EC
   COEFFICIENT_A          (0x82),  // Obs samma v�rde som EXPONENT...
   COEFFICIENT_B          (0x83),
   BASE_POINT_G           (0x84),
   BASE_POINT_R_ORDER     (0x85),
   PUBLIC_POINT_Y         (0x86),
   COFACTOR_F             (0x87);

   
   private int value;
   private boolean isSequence;

   private CVCTagEnum(int value) {
      this(value, false);
   }

   private CVCTagEnum(int value, boolean isSequence) {
      this.value = value;
      this.isSequence = isSequence;
   }

   /**
    * Returnerar taggens numeriska v�rde. 
    * @return
    */
   public int getValue(){
      return value;
   }

   /**
    * Returnerar indikering ifall detta f�lt �r av primitiv 
    * typ eller inneh�ller subf�lt (CompositeField).
    * @return
    */
   public boolean isSequence() {
      // Enligt ITU-T X.690 ska bit 6 i f�rsta byten av tv� 
      // vara 0 d� kodningen anses primitiv.
      // OBS Detta fungerar inte pga REQ_AUTHENTICATION som har v�rdet 0x67!
      //return ((value >>> 8) & 0x20) != 0;
      return isSequence;
   }

}
