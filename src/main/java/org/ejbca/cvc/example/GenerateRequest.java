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
 * Exempelkod f�r att generera ett CVCRequest med yttre signatur,
 * dvs 'certificate renewal'.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class GenerateRequest {


   public static void main(String[] args) {
      try {
         // Installera BC som provider 
         Security.addProvider(new BouncyCastleProvider());

         // Skaffa nytt nyckelpar
         KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
         keyGen.initialize(1024, new SecureRandom());
         KeyPair keyPair = keyGen.generateKeyPair();

         /* Certificate Authority Reference ska identifiera publika nyckeln som anv�ndes i det f�rra requestet  */
         CAReferenceField previousHolderRef = new CAReferenceField("SE","ABSP","00008");
         /* Certificate Holder Reference ska r�knas upp d� ett nytt nyckelpar anv�nds */
         HolderReferenceField holderRef = new HolderReferenceField("SE","ABSP","00009");

         String algorithmName = "SHA256WITHRSAANDMGF1";

         // Anropa metod i CertificateGenerator
         CVCertificate request = CertificateGenerator.createRequest(keyPair, algorithmName, holderRef);
         System.out.println(request.getAsText());

         CVCAuthenticatedRequest authRequest = CertificateGenerator.createAuthenticatedRequest(request, keyPair, algorithmName, previousHolderRef);
         System.out.println(authRequest.getAsText());
         
         FileHelper.writeFile(new File("C:/eBorder/cv_certs/request5_auth.cvcert"), authRequest.getDEREncoded());
      }
      catch( Exception e ){
         e.printStackTrace();
      }
   }

}
