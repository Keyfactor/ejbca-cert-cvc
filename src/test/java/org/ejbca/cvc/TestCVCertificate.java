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
import java.io.File;
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
import org.ejbca.cvc.example.FileHelper;

/**
 * Tests specific for CV Certificates
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TestCVCertificate
      extends TestCase implements CVCTest {


   protected void setUp() throws Exception {
      // Install Bouncy Castle as security provider 
      Security.addProvider(new BouncyCastleProvider());
   }

   protected void tearDown() throws Exception {
      // Uninstallera BC 
      Security.removeProvider("BC");
   }


   /** Check: DER-encoding/decoding of a CVCertificate should not affect its data */
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

   
   /** Check: The CVCertificate signature should be verifiable */
   public void testVerifyCertificate() throws Exception {
      // Create new key pair
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();

      CAReferenceField caRef         = new CAReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
      HolderReferenceField holderRef = new HolderReferenceField(HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);

      // This will create a self-signed certificate
      CVCertificate cert = 
         CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithRSA", AuthorizationRoleEnum.IS);
      cert.verify(keyPair.getPublic(), "BC");
      
      CardVerifiableCertificate cvc = new CardVerifiableCertificate(cert);
      cvc.verify(keyPair.getPublic(), "BC");
   }


   /** Check: Verify certificate chain */
   public void testVerifyCertificateChain() throws Exception {
      // Create key pair for CA
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair ca_KeyPair = keyGen.generateKeyPair();

      // Simulate an IS certificate that has been signed by CA
      // Create new key pair
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
         // This is expected

         is_cert.verify(ca_KeyPair.getPublic(), "BC");
      }
   }
   
   
   /** Check: Validate CVCProvider */
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

	public void testExternalCert()throws Exception {
	      byte[] bytes = FileHelper.loadFile(new File("./src/test/resources/GO_CVCA_RSA2008.cvcert"));
	      CVCertificate cvc = (CVCertificate)CertificateParser.parseCVCObject(bytes);
	      CardVerifiableCertificate cvcacert = new CardVerifiableCertificate(cvc);
	      System.out.println("CERT\n: "+cvcacert.toString());
	      cvcacert.verify(cvc.getCertificateBody().getPublicKey(), "BC");

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
      return CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithRSA", AuthorizationRoleEnum.IS);
   }

}
