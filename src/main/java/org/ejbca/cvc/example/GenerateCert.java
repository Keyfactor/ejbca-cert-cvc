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
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;


/**
 * Exempelkod f�r att generera ett CVCertificate
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class GenerateCert {


   public static void main(String[] args) {
      try {
         // Installera BC som provider 
         Security.addProvider(new BouncyCastleProvider());

         // Skaffa nytt nyckelpar
         KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
         keyGen.initialize(1024, new SecureRandom());
         KeyPair keyPair = keyGen.generateKeyPair();

         CAReferenceField caRef = new CAReferenceField("SE","CVCA-RPS","00111");
         // H�r �r CA_REF samma som HOLDER_REF eftersom vi ska ha ett self-signed CVCA-cert
         HolderReferenceField holderRef = new HolderReferenceField(caRef.getCountry(), caRef.getMnemonic(), caRef.getSequence());


         // Anropa den enklare metoden i CertificateGenerator
         CVCertificate cvc = 
            CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef);

         byte[] certData = cvc.getDEREncoded();

         String filename = "C:/eBorder/cv_certs/mycert_6.cvcert";
         FileHelper.writeFile(new File(filename), certData);

         // Debug - l�s upp bin�rfile och parsa
         certData = FileHelper.loadFile(new File(filename));
         CVCObject parsedObject = CertificateParser.parseCertificate(certData);
         System.out.println(parsedObject.getAsText(""));
      }
      catch( Exception e ){
         e.printStackTrace();
      }
   }

}
