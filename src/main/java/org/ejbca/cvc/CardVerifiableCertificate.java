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
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

/**
 * Wrapper of CVCertificate that extends java.security.cert.Certificate
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class CardVerifiableCertificate
      extends Certificate {

   private CVCertificate cvc;

   /**
    * Constructs an instance from a CVCertificate
    * @param cvc
    */
   public CardVerifiableCertificate(CVCertificate cvc) {
      super("CVC");
      this.cvc = cvc;
   }
   
   /**
    * Returns embedded CVCertificate
    * @return
    */
   public CVCertificate getCVCertificate() {
      return cvc;
   }

   @Override
   public byte[] getEncoded() throws CertificateEncodingException {
      try {
         return cvc.getDEREncoded();
      }
      catch( IOException e ){
         throw new CertificateEncodingException(e);
      }
   }

   @Override
   public PublicKey getPublicKey() {
      try {
         return cvc.getCertificateBody().getPublicKey();
      }
      catch (NoSuchFieldException e) {
         e.printStackTrace();
         return null;
      }
   }

   @Override
   public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
      verify(key, "BC");
   }

   @Override
   public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
         SignatureException {

      cvc.verify(key, sigProvider);
   }

   @Override
   public String toString() {
      return cvc.toString();
   }

}
