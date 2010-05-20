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

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Date;

import junit.framework.TestCase;

import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.cvc.example.FileHelper;
import org.ejbca.cvc.util.StringConverter;


/**
 * Tests PublicKey classes
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TestPublicKey 
   extends TestCase implements CVCTest {

   protected void setUp() throws Exception {
      // Install Bouncy Castle as security provider 
      Security.addProvider(new BouncyCastleProvider());
   }

   protected void tearDown() throws Exception {
      // Uninstall BC 
      Security.removeProvider("BC");
   }

   
   /** Check: DER encoding/decoding must not affect data */
   public void testPubliKeyField() throws Exception {
      // Create new key pair
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();

      PublicKeyRSA rsa1 = (PublicKeyRSA)KeyFactory.createInstance(keyPair.getPublic(), "SHA1WITHRSA", null);
      byte[] der = rsa1.getEncoded();

      CVCObject cvcObj = CertificateParser.parseCVCObject(der);
      assertTrue("Parsed array was not a PublicKeyRSA", (cvcObj instanceof PublicKeyRSA));

      RSAPublicKey rsaKey = (RSAPublicKey)keyPair.getPublic();

      RSAPublicKey rsa2 = (RSAPublicKey)cvcObj;  // This casting should be successful
      assertEquals("Key modulus", rsaKey.getModulus(), rsa2.getModulus());
      assertEquals("Key exponent", rsaKey.getPublicExponent(), rsa2.getPublicExponent());
      assertEquals("Key algorithm", "RSA", rsa2.getAlgorithm());
      
      PublicKeyRSA rsa3 = (PublicKeyRSA)rsa2;
      assertEquals("OIDs", rsa1.getObjectIdentifier(), rsa3.getObjectIdentifier());
   }

   
   /** Check: Some modulus values has caused problems with leading zeroes when encoding */
   public void testParseAndCreate() throws Exception {
      byte[] keydata = FileHelper.loadFile(new File("./src/test/resources/PUBLIC_KEY_RSA1024.cvc"));
      CVCPublicKey publicKey1 = (CVCPublicKey)CertificateParser.parseCVCObject(keydata);

      // Create certificate
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();
      CAReferenceField caRef = new CAReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
      HolderReferenceField holderRef = new HolderReferenceField(HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);

      // Call CertificateGenerator
      CVCertificate cvc = 
         CertificateGenerator.createTestCertificate(publicKey1, keyPair.getPrivate(), caRef, holderRef, "SHA1WithRSA", AuthorizationRoleEnum.IS );
      
      // Compare as text - these should be identical
      CVCPublicKey publicKey2 = cvc.getCertificateBody().getPublicKey();
      assertEquals("Public keys as text differ", publicKey1.getAsText(""), publicKey2.getAsText(""));

   }
   

   /** Check: Create CVC public key from a java public key - the encoded modulus should not have ant leading zeroes */
   public void testModulusValue() throws Exception {
      // Create key pair using java.security
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();
      
      PublicKeyRSA rsaKey = (PublicKeyRSA)KeyFactory.createInstance(keyPair.getPublic(), "SHA1WITHRSA", null);
      byte[] modulusData = ((ByteField)rsaKey.getSubfield(CVCTagEnum.MODULUS)).getData();
      assertTrue("Leading zero found in modulus", modulusData[0]!=0);
   }


   /** Check: Validate methods specific for Elliptic Curve public keys */
   public void testPublicKeyEC() throws Exception {
      // Test encoding of a ECPoint
      String expectedByteStr = "04013579024680";
      BigInteger affineX = new BigInteger("13579", 16);
      BigInteger affineY = new BigInteger("24680", 16);
      ECPoint point = new ECPoint(affineX, affineY);
      byte[] data = PublicKeyEC.encodePoint(point, null);
      assertEquals("Encoded ECPoint", expectedByteStr, StringConverter.byteToHex(data));
      
      // Test decoding of a ECPoint
      ECPoint decodedPoint = PublicKeyEC.decodePoint(new BigInteger(expectedByteStr,16).toByteArray());
      assertEquals("AffineX", affineX, decodedPoint.getAffineX());

      // Test with a point with an affineY that is one byte shorted than the affineX, should be 0 padded on the left
      String x = "9FDAB8773ADEE1735BB58E8D0A81C29924EC3F94D9F4B182E887CBDC7CDDD357";
      String y = "D758F858BF3C84575E93D13D072AD9255CD47F18F40A262F43A237132B55A1";
      expectedByteStr = "04"+x+"00"+y;
      affineX = new BigInteger(x, 16);
      affineY = new BigInteger(y, 16);
      point = new ECPoint(affineX, affineY);
      data = PublicKeyEC.encodePoint(point, null);
      String result = StringConverter.byteToHex(data);
      assertEquals("Encoded ECPoint", expectedByteStr, result);

      // Test with a point with an affineX that is one byte shorted than the affineY, should be 0 padded on the left
      x = "9FDAB8773ADEE1735BB58E8D0A81C29924EC3F94D9F4B182E887CBDC7CDDD3";
      y = "57D758F858BF3C84575E93D13D072AD9255CD47F18F40A262F43A237132B55A1";
      expectedByteStr = "04"+"00"+x+y;
      affineX = new BigInteger(x, 16);
      affineY = new BigInteger(y, 16);
      point = new ECPoint(affineX, affineY);
      data = PublicKeyEC.encodePoint(point, null);
      result = StringConverter.byteToHex(data);
      assertEquals("Encoded ECPoint", expectedByteStr, result);

      // Create key with BouncyCastle (v1.36 supports key lengths 192, 239 and 256)...
      // See org.bouncycastle.jce.provider.JDKKeyPairGenerator.EC
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
      keyGen.initialize(239, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();

      PublicKeyEC ecKey = (PublicKeyEC)KeyFactory.createInstance(keyPair.getPublic(), "SHA1WITHECDSA", null);
      assertTrue("ECParams is null", ecKey.getParams()!=null );
      assertEquals("Cofactor", 1, ecKey.getParams().getCofactor());
      // Test conversion using Curve parameter as well, even if it's a regular key with no strange sizes.
      data = PublicKeyEC.encodePoint(ecKey.getParams().getGenerator(), ecKey.getParams().getCurve());
      result = StringConverter.byteToHex(data);
      expectedByteStr = "04"+"0FFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF"+"7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE";
      assertEquals("Encoded ECPoint", expectedByteStr, result);
   }


   /** Check: Domain parameters shall be included when encoding only in specific cases */
   public void testPublicKeyECFields() throws Exception {
      CVCertificateBody bodyIS = createBody(AuthorizationRoleEnum.IS);
      CVCertificateBody bodyCVCA = createBody(AuthorizationRoleEnum.CVCA);

      CVCObject cvcObjIS = CertificateParser.parseCVCObject(bodyIS.getDEREncoded());
      CVCObject cvcObjCVCA = CertificateParser.parseCVCObject(bodyCVCA.getDEREncoded());
      assertTrue("CVCObj not a CVCertificateBody", cvcObjIS.getTag()==CVCTagEnum.CERTIFICATE_BODY);

      // IS certificate must contain only two EC public key subfields
      PublicKeyEC ecKey1 = (PublicKeyEC)((CVCertificateBody)cvcObjIS).getPublicKey();
      assertEquals("Number of PublicKey subfields", 2, ecKey1.getSubfields().size());

      // CVCA certificate must contain all eight EC public key subfields
      PublicKeyEC ecKey2 = (PublicKeyEC)((CVCertificateBody)cvcObjCVCA).getPublicKey();
      assertEquals("Number of PublicKey subfields", 8, ecKey2.getSubfields().size());


      // Create a request
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
      keyGen.initialize(256, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();
      CVCertificate req = CertificateGenerator.createRequest(
            keyPair, 
            "SHA256WITHECDSA",
            new HolderReferenceField("SE", "KLMNOPQ", "00001")
      );
      // All EC public key subfields must be present in a CVC-request
      CVCPublicKey pubKey = req.getCertificateBody().getPublicKey();
      assertEquals("Number of EC subfields", 8, pubKey.getSubfields().size());
   }

   
   private KeyPair createECKeyPair() throws Exception {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");

      EllipticCurve curve = new EllipticCurve(
            new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
      ECParameterSpec spec = new ECParameterSpec(
            curve,
            ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
            3); // h

      keyGen.initialize(spec);
      return keyGen.generateKeyPair();
   }

   
   private CVCertificateBody createBody(AuthorizationRoleEnum roleEnum) throws Exception {
      KeyPair keyPair = createECKeyPair();
      PublicKeyEC ecKey = (PublicKeyEC)KeyFactory.createInstance(keyPair.getPublic(), "SHA1WITHECDSA", roleEnum);

      return new  CVCertificateBody(
            new CAReferenceField("SE", "ABCDEF", "00001"),
            ecKey,
            new HolderReferenceField("SE", "KLMNOPQ", "00001"),
            roleEnum,
            AccessRightEnum.READ_ACCESS_DG3,
            new Date(),
            new Date() 
      );
   }

}
