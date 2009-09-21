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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import junit.framework.TestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.exception.ConstructionException;


/**
 * Tests Factory classes
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TestFactories 
   extends TestCase implements CVCTest {
   

   protected void setUp() throws Exception {
      // Install Bouncy Castle as security provider 
      Security.addProvider(new BouncyCastleProvider());
   }

   protected void tearDown() throws Exception {
      // Uninstall BC
      Security.removeProvider("BC");
   }

   
   /** Check: validate FieldFactory */ 
   public void testFieldFactory() throws Exception {
      AbstractDataField field = 
         FieldFactory.decodeField(CVCTagEnum.COFACTOR_F, new byte[]{ 0x01, 0x01, 0x01, 0x01 });
      assertTrue("Field is not IntegerField", (field instanceof IntegerField));
      IntegerField intField = (IntegerField)field;
      assertEquals("Data value", 16843009, intField.getValue());
      
      String dummyOID = "1.2.3.4.5.6";
      OIDField oid1 = new OIDField(dummyOID);
      OIDField oid2 = (OIDField)FieldFactory.decodeField(CVCTagEnum.OID, oid1.getEncoded());
      assertEquals("OID value not equal", oid2.getValue(), dummyOID);

      try {
         FieldFactory.decodeField(CVCTagEnum.CERTIFICATE_BODY, new byte[]{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 });
         throw new Exception("A sequence-type tag should throw IllegalArgumentException");
      }
      catch (IllegalArgumentException e) {
         // This is expected
      }
   }

   
   /** Check: validate KeyFactory */ 
   public void testKeyFactory() throws Exception {
      GenericPublicKeyField genKey = new GenericPublicKeyField();
      
      // First create an incomplete GenericPublicKeyField
      OIDField oid = AlgorithmUtil.getOIDField("SHA256WITHRSA");
      genKey.addSubfield(oid);
      try {
         KeyFactory.createInstance(genKey);
         throw new Exception("Incomplete instance of GenericPublicKeyField should throw ParseException");
      }
      catch(ConstructionException e){
         // This is expected
      }

      // Add fields for RSA
      BigInteger modulus = new BigInteger(new byte[] {0x01, 0x02, 0x03, 0x04});
      genKey.addSubfield(new ByteField(CVCTagEnum.MODULUS, modulus.toByteArray()));
      genKey.addSubfield(new ByteField(CVCTagEnum.EXPONENT, modulus.toByteArray()));

      // Create public key object and compare
      CVCPublicKey cvcPubkey = KeyFactory.createInstance(genKey);
      assertTrue("cvcPubkey not a PublicKeyRSA", (cvcPubkey instanceof PublicKeyRSA));
      PublicKeyRSA rsa1 = (PublicKeyRSA)cvcPubkey;

      assertEquals("Modulus field", modulus, rsa1.getModulus());
      assertEquals("OID", oid, rsa1.getObjectIdentifier());
      
      
      // Create new key pair
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
      keyGen.initialize(1024, new SecureRandom());
      KeyPair keyPair = keyGen.generateKeyPair();

      String algorithm = "SHA256WITHRSA";
      CVCPublicKey cvcKey2 = KeyFactory.createInstance(keyPair.getPublic(), algorithm, null);
      assertTrue("cvcKey not instanceof PublicKeyRSA", (cvcKey2 instanceof PublicKeyRSA));
      
      PublicKeyRSA rsa2 = (PublicKeyRSA)cvcKey2;
      assertEquals("Algorithm name differs", algorithm, AlgorithmUtil.getAlgorithmName(rsa2.getObjectIdentifier()));
      

      // This should return the exact same instance
      CVCPublicKey cvcPubkey2 = KeyFactory.createInstance(cvcPubkey, "DummyAlgorithm", null);
      assertTrue("CVCPublicKey objects not same instance", cvcPubkey2==cvcPubkey);
   }

   
   /** Check: validate SequenceFactory */
   public void testSequenceFactory() throws Exception {
      AbstractSequence seq = SequenceFactory.createSequence(CVCTagEnum.CV_CERTIFICATE);
      assertTrue("seq not instance of CVCertificate", (seq instanceof CVCertificate));
      
      try {
         SequenceFactory.createSequence(CVCTagEnum.EXPIRATION_DATE);
         throw new Exception("A datafield-type tag should throw IllegalArgumentException");
      }
      catch( IllegalArgumentException e){
         // This is expected
      }
   }

}
