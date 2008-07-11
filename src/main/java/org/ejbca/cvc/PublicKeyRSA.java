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

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import org.ejbca.cvc.exception.ConstructionException;


/**
 * CVC:s implementation av RSAPublicKey
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class PublicKeyRSA
      extends CVCPublicKey implements RSAPublicKey {

   private static CVCTagEnum[] allowedFields = new CVCTagEnum[] {
      CVCTagEnum.OID,
      CVCTagEnum.MODULUS, 
      CVCTagEnum.EXPONENT
   };

   @Override
   CVCTagEnum[] getAllowedFields() {
      return allowedFields;
   }

   /**
    * Skapar instans fr�n en GenericPublicKeyField
    * @param genericKey
    * @throws NoSuchFieldException
    */
   PublicKeyRSA(GenericPublicKeyField genericKey) throws ConstructionException, NoSuchFieldException {
      ByteField modulusField = (ByteField)genericKey.getSubfield(CVCTagEnum.MODULUS);
      modulusField.setShowBitLength(true);  // Vi vill se denna l�ngd vid utskrift

      addSubfield(genericKey.getSubfield(CVCTagEnum.OID));
      addSubfield(modulusField);
      addSubfield(genericKey.getSubfield(CVCTagEnum.EXPONENT));
   }


   /**
    * Skapar instans fr�n en OIDField samt PublicKey
    * @param oid
    * @param pubKey
    */
   PublicKeyRSA(OIDField oid, RSAPublicKey rsaKey) throws ConstructionException {
      super();

      addSubfield(oid);
      addSubfield(new ByteField(CVCTagEnum.MODULUS, trimByteArray(rsaKey.getModulus().toByteArray()), true));
      addSubfield(new ByteField(CVCTagEnum.EXPONENT, trimByteArray(rsaKey.getPublicExponent().toByteArray())));
   }

   
   public String getAlgorithm() {
      return "RSA";
   }

   public String getFormat() {
      return "CVC";   // TODO: Kolla denna
   }

   public BigInteger getPublicExponent() {
      try {
         ByteField exp = (ByteField)getSubfield(CVCTagEnum.EXPONENT);
         return new BigInteger(1, exp.getData());
      }
      catch( NoSuchFieldException e ){
         // Instansen har inte skapats korrekt
         throw new IllegalStateException(e);
      }
   }

   public BigInteger getModulus() {
      try {
         ByteField exp = (ByteField)getSubfield(CVCTagEnum.MODULUS);
         return new BigInteger(1, exp.getData());
      }
      catch( NoSuchFieldException e ){
         // Instansen har inte skapats korrekt
         throw new IllegalStateException(e);
      }
   }

}
