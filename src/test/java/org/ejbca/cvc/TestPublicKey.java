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
 * Klassen utf�r tester specifika f�r PublicKey-klasser
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TestPublicKey 
   extends TestCase implements CVCTest {

   protected void setUp() throws Exception {
      // Installera BC som provider 
      Security.addProvider(new BouncyCastleProvider());
   }

   protected void tearDown() throws Exception {
      // Installera BC som provider 
      Security.removeProvider("BC");
   }

   
   /** Kontroll: Kodning till/fr�n DER ska inte p�verka data */
   public void testPubliKeyField() throws Exception {
      // Skaffa nytt nyckelpar
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();

      PublicKeyRSA rsa1 = (PublicKeyRSA)KeyFactory.createInstance(keyPair.getPublic(), "SHA1WITHRSA");
      byte[] der = rsa1.getEncoded();

      CVCObject cvcObj = CertificateParser.parseCVCObject(der);
      assertTrue("Parsed array was not a PublicKeyRSA", (cvcObj instanceof PublicKeyRSA));

      RSAPublicKey rsaKey = (RSAPublicKey)keyPair.getPublic();

      RSAPublicKey rsa2 = (RSAPublicKey)cvcObj;  // Denna castning ska ocks� g� bra
      assertEquals("Key modulus", rsaKey.getModulus(), rsa2.getModulus());
      assertEquals("Key exponent", rsaKey.getPublicExponent(), rsa2.getPublicExponent());
      assertEquals("Key algorithm", "RSA", rsa2.getAlgorithm());
      
      PublicKeyRSA rsa3 = (PublicKeyRSA)rsa2;
      assertEquals("OIDs", rsa1.getObjectIdentifier(), rsa3.getObjectIdentifier());
   }

   
   /** Kontroll: Vissa modulus-v�rden har orsakat problem med inledande nollor i byte array */
   public void testParseAndCreate() throws Exception {
      byte[] keydata = FileHelper.loadFile(new File("./src/test/resources/PUBLIC_KEY_RSA1024.cvc"));
      CVCPublicKey publicKey1 = (CVCPublicKey)CertificateParser.parseCVCObject(keydata);

      // Skapa cert
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();
      CAReferenceField caRef = new CAReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
      HolderReferenceField holderRef = new HolderReferenceField(HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);

      // Anropa metod i CertificateGenerator
      CVCertificate cvc = 
         CertificateGenerator.createTestCertificate(publicKey1, keyPair.getPrivate(), caRef, holderRef );
      
      // J�mf�r som text - ska vara identiska
      CVCPublicKey publicKey2 = cvc.getCertificateBody().getPublicKey();
      assertEquals("Public keys as text differ", publicKey1.getAsText(""), publicKey2.getAsText(""));

   }
   

   /** Kontroll: Skapa cvc-nyckel fr�n genererad nyckel, DER-kodad bytearray ska d� inte ha inledande nollor */
   public void testModulusValue() throws Exception {
      // Skapa nyckel med java.security
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();
      
      PublicKeyRSA rsaKey = (PublicKeyRSA)KeyFactory.createInstance(keyPair.getPublic(), "SHA1WITHRSA");
      byte[] modulusData = ((ByteField)rsaKey.getSubfield(CVCTagEnum.MODULUS)).getData();
      assertTrue("Leading zero found in modulus", modulusData[0]!=0);
   }


   /** Kontroll: Skapa och parsa EC-nyckel korrekt */
   public void testPublicKeyEC() throws Exception {
//      byte[] derdata = FileHelper.loadFile(new File("C:/eBorder/specimen/ECC/GO_CVCA_EC256.cvcert"));
//      CVCertificate cert = CertificateParser.parseCertificate(derdata);
//      System.out.println(cert);
      
      // Testa kodning av ECPoint till byte-array
      String expectedByteStr = "04013579024680";
      BigInteger affineX = new BigInteger("13579", 16);
      BigInteger affineY = new BigInteger("24680", 16);
      ECPoint point = new ECPoint(affineX, affineY);
      byte[] data = PublicKeyEC.encodePoint(point);
      assertEquals("Encoded ECPoint", expectedByteStr, StringConverter.byteToHex(data));
      
      // Testa avkodning av ECPoint
      ECPoint decodedPoint = PublicKeyEC.decodePoint(new BigInteger(expectedByteStr,16).toByteArray());
      assertEquals("AffineX", affineX, decodedPoint.getAffineX());

      // Skapa nyckel med BouncyCastle (1.36 st�djer l�ngder 192, 239 och 256)...
      // Se org.bouncycastle.jce.provider.JDKKeyPairGenerator.EC
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
      keyGen.initialize(239, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();
      
      PublicKeyEC ecKey = (PublicKeyEC)KeyFactory.createInstance(keyPair.getPublic(), "SHA1WITHECDSA");
      assertTrue("ECParams is null", ecKey.getParams()!=null );
      assertEquals("Cofactor", 1, ecKey.getParams().getCofactor());
   }


   /** Kontroll: Dom�nparametrar ska bara komma med vid DER-kodning i vissa fall */
   public void testPublicKeyECFields() throws Exception {
      CVCertificateBody bodyIS = createBody(AuthorizationRoleEnum.IS);
      CVCertificateBody bodyCVCA = createBody(AuthorizationRoleEnum.CVCA);

      CVCObject cvcObjIS = CertificateParser.parseCVCObject(bodyIS.getDEREncoded());
      CVCObject cvcObjCVCA = CertificateParser.parseCVCObject(bodyCVCA.getDEREncoded());
      assertTrue("CVCObj not a CVCertificateBody", cvcObjIS.getTag()==CVCTagEnum.CERTIFICATE_BODY);

      // Endast tv� subf�lt f�rv�ntas i IS-cert
      PublicKeyEC ecKey1 = (PublicKeyEC)((CVCertificateBody)cvcObjIS).getPublicKey();
      assertEquals("Number of PublicKey subfields", 2, ecKey1.getSubfields().size());

      // �tta subf�lt f�rv�ntas i ett CVCA-cert
      PublicKeyEC ecKey2 = (PublicKeyEC)((CVCertificateBody)cvcObjCVCA).getPublicKey();
      assertEquals("Number of PublicKey subfields", 8, ecKey2.getSubfields().size());


      // Skapa ett request
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
      keyGen.initialize(256, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();
      CVCertificate req = CertificateGenerator.createRequest(
            keyPair, 
            "SHA256WITHECDSA",
            new HolderReferenceField("SE", "KLMNOPQ", "00001")
      );
      // �tta subf�lt f�rv�ntas i ett CVC-request
      CVCPublicKey pubKey = req.getCertificateBody().getPublicKey();
      assertEquals("Number of EC subfields", 8, pubKey.getSubfields().size());
   }

   
   private KeyPair createECKeyPair() throws Exception {
      // Ett annat s�tt att skapa nyckeln
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
      PublicKeyEC ecKey = (PublicKeyEC)KeyFactory.createInstance(keyPair.getPublic(), "SHA1WITHECDSA");

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
