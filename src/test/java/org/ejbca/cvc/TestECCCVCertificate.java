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
import org.ejbca.cvc.example.FileHelper;

/**
 * Tests specific for ECC CV Certificates
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TestECCCVCertificate
extends TestCase implements CVCTest {


	protected void setUp() throws Exception {
		// Install BC as provider 
		Security.addProvider(new BouncyCastleProvider());
	}

	protected void tearDown() throws Exception {
		// Remove BC provider 
		Security.removeProvider("BC");
	}


	/** Check: Creating testcertificate + kodning to/from DER should not affect contents */
	public void testEncoding() throws Exception {
		//
		// Test a CVCA certificate
		//

		// A CVCA certificate will contain the complete ECC params 
		CVCertificate cert1 = createTestCertificate(AuthorizationRoleEnum.CVCA);

		byte[] pubkey1 = cert1.getCertificateBody().getPublicKey().getDEREncoded();

		byte[] der = cert1.getDEREncoded();

		CVCObject cvcObj = CertificateParser.parseCertificate(der);
		assertTrue("Parsed object is not a CVCertificate: " + cvcObj.getTag(), (cvcObj instanceof CVCertificate));

		CVCertificate cert2 = (CVCertificate)cvcObj;
		System.out.println("CERT1");
		System.out.println(cert1.getAsText());
//		System.out.println("CERT2");
//		System.out.println(cert2.getAsText());
		assertEquals("Certificates as text differ", cert1.getAsText(), cert2.getAsText());

		byte[] pubkey2 = cert2.getCertificateBody().getPublicKey().getDEREncoded();
		assertTrue("DER-coded public keys not equal", Arrays.equals(pubkey1, pubkey2));

		// For CVCA certificates the whole public key with parameters is available
		// Verify cert1 with cert1
		cert1.verify(cert1.getCertificateBody().getPublicKey(), "BC");
		
		// Verify cert2 with cert2
		cert2.verify(cert2.getCertificateBody().getPublicKey(), "BC");

		// Verify cert1 with cert2
		cert1.verify(cert2.getCertificateBody().getPublicKey(), "BC");

		//
		// Test an IS certificate
		//
		// An IS certificate will not contain the complete ECC params 
		cert1 = createTestCertificate(AuthorizationRoleEnum.IS);

		pubkey1 = cert1.getCertificateBody().getPublicKey().getDEREncoded();
		der = cert1.getDEREncoded();

		cvcObj = CertificateParser.parseCertificate(der);
		assertTrue("Parsed object is not a CVCertificate: " + cvcObj.getTag(), (cvcObj instanceof CVCertificate));

		cert2 = (CVCertificate)cvcObj;
//		System.out.println("CERT1");
//		System.out.println(cert1.getAsText());
//		System.out.println("CERT2");
//		System.out.println(cert2.getAsText());
		assertEquals("Certificates as text differ", cert1.getAsText(), cert2.getAsText());

		pubkey2 = cert2.getCertificateBody().getPublicKey().getDEREncoded();
		assertTrue("DER-coded public keys not equal", Arrays.equals(pubkey1, pubkey2));
		
	}


	/** Check: the signature for a CardVerifiableCertificate should verify */
	public void testVerifyCertificate() throws Exception {
		// Skaffa nytt nyckelpar
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
		keyGen.initialize(239, new SecureRandom());
		KeyPair keyPair = keyGen.generateKeyPair();

		CAReferenceField caRef         = new CAReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
		HolderReferenceField holderRef = new HolderReferenceField(HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);

		// Detta blir ett self-signed certifikat
		CVCertificate cert = 
			CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithECDSA", AuthorizationRoleEnum.IS);
		cert.verify(keyPair.getPublic(), "BC");

		CardVerifiableCertificate cvc = new CardVerifiableCertificate(cert);
		cvc.verify(keyPair.getPublic(), "BC");
	}


	/** Check: A is should be possible to verify a certificate chain */
	public void testVerifyCertificateChain() throws Exception {
		// Create keypair for CA
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
		keyGen.initialize(239, new SecureRandom());
		KeyPair ca_KeyPair = keyGen.generateKeyPair();

		// Simulate an IS certificate signed by the CA
		// New keypair
		keyGen.initialize(239, new SecureRandom());
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
				"SHA256WithECDSA",
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
			// This should work well in the other hand
			is_cert.verify(ca_KeyPair.getPublic(), "BC");
		}
	}


	/** Check: DER-encoded CV-certificate should be generated from a CertificateFactory */
	public void testSecurityProvider() throws Exception {
		Security.addProvider(new CVCProvider());

		CVCertificate cvc = createTestCertificate(AuthorizationRoleEnum.IS);

		CertificateFactory factory = CertificateFactory.getInstance("CVC");
		ByteArrayInputStream bin = new ByteArrayInputStream(cvc.getDEREncoded());
		Certificate cert = factory.generateCertificate(bin);

		assertTrue("cert not a CardVerifiableCertificate", (cert instanceof CardVerifiableCertificate));

		String expectedFormat = "CVC";
		assertEquals("Type is not " + expectedFormat, expectedFormat, cert.getType());
		assertEquals("Key format is not " + expectedFormat, expectedFormat, cert.getPublicKey().getFormat());

		CardVerifiableCertificate cc = (CardVerifiableCertificate)cert;
		CVCertificate cert2 = cc.getCVCertificate();
		assertEquals("Certificates as text differ", cvc.getAsText(), cert2.getAsText());

		Security.removeProvider("CVC");
	}

	
	public void testExternalCert()throws Exception {
	      //byte[] bytes = FileHelper.loadFile(new File("./src/test/resources/GO_CVCA_EC256.cvcert"));
	      byte[] bytes = FileHelper.loadFile(new File("./src/test/resources/C_CZCVCADCZ000.cvcert"));
	      CVCertificate cvc = (CVCertificate)CertificateParser.parseCVCObject(bytes);
	      CardVerifiableCertificate cvcacert = new CardVerifiableCertificate(cvc);
	      System.out.println("CERT\n: "+cvcacert.toString());
	      cvcacert.verify(cvc.getCertificateBody().getPublicKey(), "BC");

	}
	

	// Helper method to create a certificate
	private CVCertificate createTestCertificate(AuthorizationRoleEnum role) throws Exception {
		// Create key with BouncyCastle (1.36 supports lengths 192, 239 och 256)...
		// See org.bouncycastle.jce.provider.JDKKeyPairGenerator.EC
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
		keyGen.initialize(239, new SecureRandom());
		KeyPair keyPair = keyGen.generateKeyPair();

		CAReferenceField caRef = new CAReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
		HolderReferenceField holderRef = new HolderReferenceField(HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);

		// Call method in CertificateGenerator
		return CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithECDSA", role);
	}

}
