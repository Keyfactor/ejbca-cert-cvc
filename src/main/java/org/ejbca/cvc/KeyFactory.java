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
 * Tiny factory for creating instances of (subclasses to) CVCPublicKey
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class KeyFactory {

   /**
    * Constructs instance from a PublicKey and a hash algorithm
    * @param pubKey
    * @param algorithmName @see AlgorithmUtil
    * @param authRole role of certificate holder (affects creation of PublicKeyEC instances)
    * @return
    */
   public static CVCPublicKey createInstance(PublicKey pubKey, String algorithmName, AuthorizationRole authRole) throws ConstructionException {
      
      if( pubKey instanceof CVCPublicKey ){
         // Object is already of the expected type
         return (CVCPublicKey)pubKey;
      }

      // Here we can use algorithmName to the find the corresponding OID
      // which in turn identifies the type of key (RSA or EC)
      CVCPublicKey cvcPublicKey = null;
      OIDField oid = AlgorithmUtil.getOIDField(algorithmName);
      if( oid.getValue().startsWith(CVCObjectIdentifiers.id_TA_RSA) ){
         // It's RSA
         cvcPublicKey = new PublicKeyRSA(oid, (RSAPublicKey)pubKey);
      }
      else if( oid.getValue().startsWith(CVCObjectIdentifiers.id_TA_ECDSA) ){
         // It's EC
         cvcPublicKey = new PublicKeyEC(oid, (ECPublicKey)pubKey, authRole);
      }
      else {
         throw new IllegalArgumentException("Unknown key type: " + oid);
      }
      return cvcPublicKey;
   }
   
   /**
    * Constructs instance from a PublicKey and a hash algorithm. This seemingly redundant
    * overloaded method is for binary (.class file) backwards compatibility.
    * It is NOT deprecated to use these argument types.
    */
   public static CVCPublicKey createInstance(PublicKey pubKey, String algorithmName, AuthorizationRoleEnum authRole) throws ConstructionException {
      return createInstance(pubKey, algorithmName, (AuthorizationRole)authRole);
   }

   /**
    * Constructs instance from a GenericPublicKeyField (i e when parsing DER-encoded data)
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
    * Special helper method that deals with the problem that two different 
    * public key tags have the same value. 
    * TODO: This handling is subject for improvement!
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
         // OK, the field hasn't been added - check if 'fromTag' is available
         field = (ByteField)generic.getOptionalSubfield(fromTag);
         if( field!=null ) {
            // Yes, copy the value and add it as 'toTag'
            generic.addSubfield(new ByteField(toTag, field.getData()));
         }
      }
   }

}
