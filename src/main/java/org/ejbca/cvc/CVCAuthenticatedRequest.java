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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import org.ejbca.cvc.exception.ConstructionException;



/**
 * Representerar ett CVC-request med en yttre signatur.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class CVCAuthenticatedRequest
      extends AbstractSequence {


   private static CVCTagEnum[] allowedFields = new CVCTagEnum[] {
      CVCTagEnum.CV_CERTIFICATE, 
      CVCTagEnum.CA_REFERENCE,
      CVCTagEnum.SIGNATURE
   };

   @Override
   CVCTagEnum[] getAllowedFields() {
      return allowedFields;
   }

   /**
    * Defaultkonstruktorn ska ha begr�nsad synlighet
    */
   CVCAuthenticatedRequest() {
      super(CVCTagEnum.REQ_AUTHENTICATION);
   }

   /**
    * Skapar instans fr�n certifikat, caRef samt signatur
    * @param cvcert
    * @param caReference
    * @param signatureData
    */
   public CVCAuthenticatedRequest(CVCertificate cvcert, CAReferenceField caReference, byte[] signatureData) 
   throws ConstructionException {
      this();
      
      addSubfield(cvcert);
      addSubfield(caReference);
      addSubfield(new ByteField(CVCTagEnum.SIGNATURE, signatureData));
   }

   /**
    * Returnerar det inb�ddade requestet
    * @return
    */
   public CVCertificate getRequest() throws NoSuchFieldException {
      return (CVCertificate)getSubfield(CVCTagEnum.CV_CERTIFICATE);
   }

   /**
    * Returnerar CA_REFERENCE
    * @return
    */
   public CAReferenceField getAuthorityReference() throws NoSuchFieldException {
      return (CAReferenceField)getSubfield(CVCTagEnum.CA_REFERENCE);
   }

   /**
    * Returnerar requestets signatur
    * @return
    */
   public byte[] getSignature() throws NoSuchFieldException {
      return ((ByteField)getSubfield(CVCTagEnum.SIGNATURE)).getData();
   }


   /**
    * Verifierar att objektet signerats med den privata nyckeln som 
    * �r associerad med angiven publik nyckel.
    * @param pubKey
    * @throws CertificateException
    * @throws NoSuchAlgorithmException
    * @throws InvalidKeyException
    * @throws NoSuchProviderException
    * @throws SignatureException
    */
   public void verify(PublicKey pubKey) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
      try {
         // M�ste hitta hashalgoritmen
         String algorithm = "";
         if( pubKey instanceof CVCPublicKey ){
            // Om argumentet �r CVCPublicKey s� finns informationen d�r
            CVCPublicKey cvcKey = (CVCPublicKey)pubKey;
            algorithm = AlgorithmUtil.getAlgorithmName(cvcKey.getObjectIdentifier());
         }
         else {
            // I annat fall antar vi att requestets inre signatur har samma
            // hashalgoritm som den yttre!
            CVCPublicKey cvcKey = getRequest().getCertificateBody().getPublicKey();
            algorithm = AlgorithmUtil.getAlgorithmName(cvcKey.getObjectIdentifier());
         }
         Signature sign = Signature.getInstance(algorithm);
         
         // Verifiera signatur
         TBSData tbs = TBSData.getInstance(getRequest());
         sign.initVerify(pubKey);
         sign.update(tbs.getEncoded());
         if( !sign.verify(getSignature()) ){
            throw new SignatureException("Signature verification failed!");
         }
      }
      catch( NoSuchFieldException e ){
         throw new CertificateException("CV-Certificate is corrupt", e);
      }
      catch( IOException e ){
         throw new CertificateException("CV-Certificate is corrupt", e);
      }
   }

   /**
    * Bekv�mlighetsmetod
    */
   public String toString() {
      return getAsText("", true);
   }

}
