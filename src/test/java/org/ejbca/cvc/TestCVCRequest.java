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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import junit.framework.TestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Tests CVCRequest
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TestCVCRequest
      extends TestCase implements CVCTest {


   protected void setUp() throws Exception {
      // Install Bouncy Castle as security provider 
      Security.addProvider(new BouncyCastleProvider());
   }

   protected void tearDown() throws Exception {
      // Uninstall BC 
      Security.removeProvider("BC");
   }


   /** Check: OID should have been set to a specific value */
   public void testCVCRequestOID() throws Exception {
      String algorithmName = "SHA256withRSA";

      CVCertificate certRequest = createTestRequest(algorithmName);
      OIDField oid = certRequest.getCertificateBody().getPublicKey().getObjectIdentifier();
      assertEquals("OID not equal", "0.4.0.127.0.7.2.2.2.1.2", oid.getValue());
   }


   /** Check: CARef that is created in CertificateGenerator should been given the same values as Holder Ref */
   public void testCVCAuthorityReference() throws Exception {
      String algorithmName = "SHA1withRSA";

      CVCertificate certRequest = createTestRequest(algorithmName);
      String caRef = certRequest.getCertificateBody().getAuthorityReference().getConcatenated();
      assertEquals("CA_REF not equal", HR_COUNTRY_CODE+HR_HOLDER_MNEMONIC+HR_SEQUENCE_NO, caRef);

      certRequest = createTestRequestNoCA(algorithmName);
      assertNull("CAReference", certRequest.getCertificateBody().getAuthorityReference());
   }

   /** Check: DER encoding/decoding of a Request should not affect the data */
   public void testEncoding() throws Exception {
      String algorithmName = "SHA1withRSA";
      CVCertificate certReq1 = createTestRequest(algorithmName);
      byte[] derdata = certReq1.getDEREncoded();
      
      CVCertificate certReq2 = CertificateParser.parseCertificate(derdata);
      assertEquals("Request as text", certReq1.getAsText(""), certReq2.getAsText(""));
      
      OIDField oid = certReq2.getCertificateBody().getPublicKey().getObjectIdentifier();
      assertEquals("Algorithm name", algorithmName.toUpperCase(), AlgorithmUtil.getAlgorithmName(oid));
   }

   
   /** Check: DER encoding/decoding of a CVCAuthenticatedRequest should not affect the data */
   public void testAuthRequest() throws Exception {
      String algorithmName = "SHA256WITHRSA";
      CVCAuthenticatedRequest authRequest = createTestAuthRequest(null, algorithmName);
      byte[] derData = authRequest.getDEREncoded();
      
      CVCAuthenticatedRequest authRequest2 = (CVCAuthenticatedRequest)CertificateParser.parseCVCObject(derData);
      assertEquals("Requests as text", authRequest.getAsText(""), authRequest2.getAsText(""));
   }
   
   
   /** Check: Verify a request's outer signature */
   public void testVerifyRequest() throws Exception {
      String algName = "SHA256WITHRSA";

      // Create key pair 
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();
      CVCAuthenticatedRequest authReq = createTestAuthRequest(keyPair, algName);
      
      authReq.verify(keyPair.getPublic());
   }
   

   // Creates a request (CVCertificate)
   private CVCertificate createTestRequest(String algName) throws Exception {
      // Create key pair
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();

      CAReferenceField caRef = new CAReferenceField(HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);
      HolderReferenceField holderRef = new HolderReferenceField(HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);

      // Call CertificateGenerator
      return CertificateGenerator.createRequest(keyPair, algName, caRef, holderRef);
   }

   // Creates a request (CVCertificate) without caRef
   private CVCertificate createTestRequestNoCA(String algName) throws Exception {
      // Create key pair
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();

      CAReferenceField caRef = null;
      HolderReferenceField holderRef = new HolderReferenceField(HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);

      // Call CertificateGenerator
      return CertificateGenerator.createRequest(keyPair, algName, caRef, holderRef);
   }

   // Creates a request (CVCAuthenticatedRequest)
   private CVCAuthenticatedRequest createTestAuthRequest(KeyPair signingKeyPair, String algName) throws Exception {
      CAReferenceField caRef = new CAReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);

      // Call CertificateGenerator
      CVCertificate certReq = createTestRequest(algName);

      // Create key pair for outer signature (unless sent as an argument)
      KeyPair signKeys = signingKeyPair;
      if( signKeys==null ){
         KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
         keyGen.initialize(1024, new SecureRandom());
         signKeys = keyGen.generateKeyPair();
      }
      return CertificateGenerator.createAuthenticatedRequest(certReq, signKeys, algName, caRef);
   }

}
