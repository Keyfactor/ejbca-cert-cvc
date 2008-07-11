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
 * Detta �r en generisk public-key klass som endast hanteras medans man 
 * parsar upp en byte-array inneh�llande en nyckel av typen RSA eller EC.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class GenericPublicKeyField
      extends AbstractSequence {


   private static CVCTagEnum[] allowedFields = new CVCTagEnum[] {
      CVCTagEnum.OID,
      CVCTagEnum.MODULUS, 
      CVCTagEnum.EXPONENT,
      CVCTagEnum.COEFFICIENT_A,
      CVCTagEnum.COEFFICIENT_B,
      CVCTagEnum.BASE_POINT_G,
      CVCTagEnum.BASE_POINT_R_ORDER,
      CVCTagEnum.PUBLIC_POINT_Y,
      CVCTagEnum.COFACTOR_F
   };

   @Override
   CVCTagEnum[] getAllowedFields() {
      return allowedFields;
   }

   GenericPublicKeyField() {
      super(CVCTagEnum.PUBLIC_KEY);
   }

   /**
    * Hj�lpmetod f�r att enklare f� tag p� ett visst f�lt
    * @param tag
    * @return
    * @throws NoSuchFieldException
    */
   AbstractDataField getField(CVCTagEnum tag) throws NoSuchFieldException {
      return (AbstractDataField)getSubfield(tag);
   }

}
