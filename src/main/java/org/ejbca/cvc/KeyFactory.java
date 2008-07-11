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

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.ejbca.cvc.exception.ConstructionException;


/**
 * Liten fabrik f�r att skapa instanser av CVCPublicKey
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class KeyFactory {

   /**
    * Skapar instans fr�n en befintlig PublicKey samt namnet p� hash-algoritm
    * @param pubKey
    * @param algorithmName @see AlgorithmUtil
    * @return
    */
   static CVCPublicKey createInstance(PublicKey pubKey, String algorithmName) throws ConstructionException {
      
      if( pubKey instanceof CVCPublicKey ){
         // �r redan av f�rv�ntad typ
         return (CVCPublicKey)pubKey;
      }

      // I annat f�r vi utnyttja algorithmName f�r att hitta OID
      // som i sin tur identifierar typ av nyckel (RSA eller EC)
      CVCPublicKey cvcPublicKey = null;
      OIDField oid = AlgorithmUtil.getOIDField(algorithmName);
      if( oid.getValue().startsWith(CVCObjectIdentifiers.id_TA_RSA) ){
         // Det �r RSA
         cvcPublicKey = new PublicKeyRSA(oid, (RSAPublicKey)pubKey);
      }
      else if( oid.getValue().startsWith(CVCObjectIdentifiers.id_TA_ECDSA) ){
         // Det �r EC
         cvcPublicKey = new PublicKeyEC(oid, (ECPublicKey)pubKey);
      }
      else {
         throw new IllegalArgumentException("Unknown key type: " + oid);
      }
      return cvcPublicKey;
   }

   /**
    * Skapar instans fr�n en GenericPublicKeyField (dvs vid parsning av DER-kodat data)
    * @param genericKey
    * @return
    */
   static CVCPublicKey createInstance(GenericPublicKeyField genericKey) throws ConstructionException {
      CVCPublicKey cvcPublicKey = null;

      try {
         OIDField oid = (OIDField)genericKey.getOptionalSubfield(CVCTagEnum.OID);
         if( oid.getValue().startsWith(CVCObjectIdentifiers.id_TA_RSA) ){
            copyField(CVCTagEnum.COEFFICIENT_A, CVCTagEnum.EXPONENT, genericKey);
            cvcPublicKey = new PublicKeyRSA(genericKey);
         }
         else if( oid.getValue().startsWith(CVCObjectIdentifiers.id_TA_ECDSA) ){
            copyField(CVCTagEnum.EXPONENT, CVCTagEnum.COEFFICIENT_A, genericKey);
            cvcPublicKey = new PublicKeyEC(genericKey);
         }
         else {
            throw new IllegalArgumentException("Unknown public key OID: " + oid.getValue());
         }
      }
      catch( NoSuchFieldException e ){
         throw new ConstructionException(e);
      }
      return cvcPublicKey;
   }

   /**
    * L�gger till nytt bytef�lt med tagg 'toTag' med data fr�n f�lt 'fromTag',
    * om denna inte redan finns. Kan endast anv�ndas i de fall tv� taggar har
    * samma v�rde. Speciall�sning som b�r arbetas bort!
    * @param fromTag
    * @param toTag
    * @param generic
    */
   private static void copyField(CVCTagEnum fromTag, CVCTagEnum toTag, GenericPublicKeyField generic) throws ConstructionException {
      if( fromTag.getValue()!=toTag.getValue() ){
         throw new IllegalArgumentException("Tag values are not equal");
      }
      ByteField field = (ByteField)generic.getOptionalSubfield(toTag);
      if( field==null ){
         // F�ltet fanns inte - kolla om det andra f�ltet finns att kopiera
         field = (ByteField)generic.getOptionalSubfield(fromTag);
         if( field!=null ) {
            // Ok, skapa en kopia av datat med en annan tagg
            generic.addSubfield(new ByteField(toTag, field.getData()));
         }
      }
   }

}
