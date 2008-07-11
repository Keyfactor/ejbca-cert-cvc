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
 * 
 * Ett Card Verifyable Certificate i enlighet med specifikation f�r EAC 1.11.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class CVCertificate extends AbstractSequence {

   private static CVCTagEnum[] allowedFields = new CVCTagEnum[] {
      CVCTagEnum.CERTIFICATE_BODY, 
      CVCTagEnum.SIGNATURE 
   };

   @Override
   CVCTagEnum[] getAllowedFields() {
      return allowedFields;
   }


   /**
    * Default konstruktor
    */
   CVCertificate(){
      super(CVCTagEnum.CV_CERTIFICATE);
   }

   

   /**
    * Skapar instans av en CVCRequestBody samt dess signatur
    * @param body
    * @param signatureData
    * @throws IllegalArgumentException om n�got argument �r null
    */
   CVCertificate(CVCertificateBody body, byte[] signatureData) throws ConstructionException {
      this();
      
      if( body==null ){
         throw new IllegalArgumentException("body is null");
      }
      if( signatureData==null || signatureData.length==0 ){
         throw new IllegalArgumentException("signatureData is null or empty");
      }

      addSubfield(body);
      addSubfield(new ByteField(CVCTagEnum.SIGNATURE, signatureData));
   }

   /**
    * Returnerar inb�ddad CertificateBody
    * @return
    */
   public CVCertificateBody getCertificateBody() throws NoSuchFieldException {
      return (CVCertificateBody)getSubfield(CVCTagEnum.CERTIFICATE_BODY);
   }

   /**
    * Returnerar certifikatets signatur
    * @return
    */
   public byte[] getSignature() throws NoSuchFieldException {
      return ((ByteField)getSubfield(CVCTagEnum.SIGNATURE)).getData();
   }


   /**
    * Returnerar certifikatet som text
    */
   public String toString() {
      return getAsText("");
   }


   /**
    * Verifierar certifikatets signatur
    */
   public void verify(PublicKey key, String provider) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
      try {
         // Kolla upp OID, d�r kodas hash-algoritmen ocks�
         OIDField oid = getCertificateBody().getPublicKey().getObjectIdentifier();
         Signature sign = Signature.getInstance(AlgorithmUtil.getAlgorithmName(oid), provider);
         
         // Verifiera signatur
         TBSData tbs = TBSData.getInstance(getCertificateBody());

         sign.initVerify(key);
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

}
