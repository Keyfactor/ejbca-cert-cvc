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

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import junit.framework.TestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCProvider;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;

/**
 * Tester specifika f�r CVCertificate
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TestCVCertificate
      extends TestCase implements CVCTest {


   protected void setUp() throws Exception {
      // Installera BC som provider 
      Security.addProvider(new BouncyCastleProvider());
   }

   protected void tearDown() throws Exception {
      // Installera BC som provider 
      Security.removeProvider("BC");
   }


   /** Kontroll: Skapande av testcert + kodning till/fr�n DER ska inte p�verka inneh�llet */
   public void testEncoding() throws Exception {

      CVCertificate cert1 = createTestCertificate();
      
      byte[] pubkey1 = cert1.getCertificateBody().getPublicKey().getDEREncoded();

      byte[] der = cert1.getDEREncoded();
      
      CVCObject cvcObj = CertificateParser.parseCertificate(der);
      assertTrue("Parsed object is not a CVCertificate: " + cvcObj.getTag(), (cvcObj instanceof CVCertificate));
      
      CVCertificate cert2 = (CVCertificate)cvcObj;
      assertEquals("Certificates as text differ", cert1.getAsText(), cert2.getAsText());

      byte[] pubkey2 = cert2.getCertificateBody().getPublicKey().getDEREncoded();
      assertTrue("DER-coded public keys not equal", Arrays.equals(pubkey1, pubkey2));
   }

   
   /** Kontroll: signaturen f�r ett skapat CardVerifiableCertificate ska g� att verifiera */
   public void testVerifyCertificate() throws Exception {
      // Skaffa nytt nyckelpar
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();

      CAReferenceField caRef         = new CAReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
      HolderReferenceField holderRef = new HolderReferenceField(HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);

      // Detta blir ett self-signed certifikat
      CVCertificate cert = 
         CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef);
      cert.verify(keyPair.getPublic(), "BC");
      
      CardVerifiableCertificate cvc = new CardVerifiableCertificate(cert);
      cvc.verify(keyPair.getPublic(), "BC");
   }


   /** Kontroll: En certifikatkedja ska g� att verifiera */
   public void testVerifyCertificateChain() throws Exception {
      // Skaffa nyckelpar f�r CA
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair ca_KeyPair = keyGen.generateKeyPair();

      // Simulera ett IS-cert som signerats av CA
      // Skaffa nytt nyckelpar
      keyGen.initialize(1024, new SecureRandom());
      KeyPair is_KeyPair = keyGen.generateKeyPair();
      CAReferenceField caRef         = new CAReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
      HolderReferenceField holderRef = new HolderReferenceField(HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);
      Calendar cal = Calendar.getInstance();
      Date dateFrom = cal.getTime();
      cal.add(Calendar.DAY_OF_MONTH, 3);
      Date dateTo = cal.getTime();
      CVCertificate is_cert = CertificateGenerator.createCertificate(
            is_KeyPair.getPublic(), 
            ca_KeyPair.getPrivate(), 
            "SHA256WithRSA",
            caRef, 
            holderRef,
            AuthorizationRoleEnum.IS,
            AccessRightEnum.READ_ACCESS_DG3_AND_DG4,
            dateFrom,
            dateTo,
            "BC"); 
      
      try {
         is_cert.verify(is_KeyPair.getPublic(), "BC");
         throw new Exception("Verifying with holder's public key should not work!");
      }
      catch( SignatureException e ){
         // Detta ska d�remot g� bra
         is_cert.verify(ca_KeyPair.getPublic(), "BC");
      }
   }
   
   
   /** Kontroll: DER-kodat CV-certifikat ska kunna genereras fr�n en CertificateFactory */
   public void testSecurityProvider() throws Exception {
      Security.addProvider(new CVCProvider());

      CVCertificate cvc = createTestCertificate();
      
      CertificateFactory factory = CertificateFactory.getInstance("CVC");
      ByteArrayInputStream bin = new ByteArrayInputStream(cvc.getDEREncoded());
      Certificate cert = factory.generateCertificate(bin);
      
      assertTrue("cert not a CardVerifiableCertificate", (cert instanceof CardVerifiableCertificate));
      
      String expectedFormat = "CVC";
      assertEquals("Type is not " + expectedFormat, expectedFormat, cert.getType());
      assertEquals("Key format is not " + expectedFormat, expectedFormat, cert.getPublicKey().getFormat());
      
      Security.removeProvider("CVC");
   }


   // Hj�lpmetod f�r att skapa ett cert
   private CVCertificate createTestCertificate() throws Exception {
      // Skaffa nytt nyckelpar
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();

      CAReferenceField caRef = new CAReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
      HolderReferenceField holderRef = new HolderReferenceField(HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);

      // Anropa metod i CertificateGenerator
      return CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef);
   }

}
