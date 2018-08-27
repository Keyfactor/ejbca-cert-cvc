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
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;


/**
 * Example code for generating a CVCertificate
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public final class GenerateCert {

	private GenerateCert() {}

   public static void main(final String[] args) {
      try {
         // Install BC as security provider 
         Security.addProvider(new BouncyCastleProvider());

         // Create a new key pair
         final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
         keyGen.initialize(1024, new SecureRandom());
         final KeyPair keyPair = keyGen.generateKeyPair();

         final CAReferenceField caRef = new CAReferenceField("SE","PASS-CVCA","00111");
         // Here we set CA_REF to the same value as HOLDER_REF since we want a self-signed CVCA-certificate
         final HolderReferenceField holderRef = new HolderReferenceField(caRef.getCountry(), caRef.getMnemonic(), caRef.getSequence());

         // Use the simpler method CertificateGenerator for this test purpose
         final CVCertificate cvc = 
            CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithRSA", AuthorizationRoleEnum.IS);

         byte[] certData = cvc.getDEREncoded();

         // Write the certificate data to a file
         String filename = "C:/cv_certs/mycert1.cvcert";
         FileHelper.writeFile(new File(filename), certData);

         // Test - read the file again and parse its contents
         certData = FileHelper.loadFile(new File(filename));
         CVCObject parsedObject = CertificateParser.parseCertificate(certData);
         System.out.println(parsedObject.getAsText("")); // NOPMD
      }
      catch( Exception e ){
         e.printStackTrace(); // NOPMD
      }
   }

}
