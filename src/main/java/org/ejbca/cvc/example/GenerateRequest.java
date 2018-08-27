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
package org.ejbca.cvc.example;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;


/**
 * Example code for generating a CVC request having an outer signature,
 * i e request used for certificate renewal.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public final class GenerateRequest {

	private GenerateRequest() {}

   public static void main(final String[] args) {
      try {
         // Install Bouncy Castle as security provider 
         Security.addProvider(new BouncyCastleProvider());

         // Create a new key pair
         final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
         keyGen.initialize(1024, new SecureRandom());
         final KeyPair keyPair = keyGen.generateKeyPair();

         /* Certificate Authority Reference shall identify the public key in the last request */
         final CAReferenceField previousHolderRef = new CAReferenceField("SE","PASSRD1","00008");
         /* Certificate Holder Reference is incremented to reflect the new key pair */
         final HolderReferenceField holderRef = new HolderReferenceField("SE","PASSRD1","00009");

         final String algorithmName = "SHA256WITHRSAANDMGF1";

         // Call CertificateGenerator
         CVCertificate request = CertificateGenerator.createRequest(keyPair, algorithmName, holderRef);
         System.out.println(request.getAsText()); // NOPMD

         CVCAuthenticatedRequest authRequest = CertificateGenerator.createAuthenticatedRequest(request, keyPair, algorithmName, previousHolderRef);
         System.out.println(authRequest.getAsText()); // NOPMD
         
         FileHelper.writeFile(new File("C:/cv_certs/request1.cvcert"), authRequest.getDEREncoded());
      }
      catch( Exception e ){
         e.printStackTrace(); // NOPMD
      }
   }

}
