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
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Calendar;

import junit.framework.TestCase;

/**
 * Tests basic functionality for AbstractDataField
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TestDatafields
      extends TestCase implements CVCTest {

   // Arrays containing DER-encoded lengths
   private static final byte[] ENCODED_LENGTH_7    = new byte[]{ 0x07 };
   private static final byte[] ENCODED_LENGTH_127  = new byte[]{ 0x7F };
   private static final byte[] ENCODED_LENGTH_128  = new byte[]{ (byte)0x81, (byte)0x80 };
   private static final byte[] ENCODED_LENGTH_1288 = new byte[]{ (byte)0x82, 0x05, 0x08 };
   
   protected void setUp() throws Exception {
      super.setUp();
   }

   protected void tearDown() throws Exception {
      super.tearDown();
   }

   
   /** Check: DER-encoding of length must be done by specific rules */
   public void testLengthEncoding() throws Exception {
      
      int len = 7;
      byte[] derData = CVCObject.encodeLength(len);
      assertTrue("Encoding of length " + len, Arrays.equals(ENCODED_LENGTH_7, derData));
      
      len = 127;
      derData = CVCObject.encodeLength(len);
      assertTrue("Encoding of length " + len, Arrays.equals(ENCODED_LENGTH_127, derData));

      len = 128;
      derData = CVCObject.encodeLength(len);
      assertTrue("Encoding of length " + len, Arrays.equals(ENCODED_LENGTH_128, derData));

      len = 1288;
      derData = CVCObject.encodeLength(len);
      assertTrue("Encoding of length " + len, Arrays.equals(ENCODED_LENGTH_1288, derData));
   }

   
   /** Check: Decoding of length */
   public void testReadLength() throws Exception {
      assertEquals(7,    readLength(ENCODED_LENGTH_7   ));
      assertEquals(127,  readLength(ENCODED_LENGTH_127 ));
      assertEquals(128,  readLength(ENCODED_LENGTH_128 ));
      assertEquals(1288, readLength(ENCODED_LENGTH_1288));
   }

   // Helper method that decodes length value from a byte array
   private int readLength(byte[] buf) throws IOException {
      ByteArrayInputStream bin = null;
      try {
         bin = new ByteArrayInputStream(buf);
         DataInputStream din = new DataInputStream(bin);
         return CVCObject.decodeLength(din);
      }
      finally {
         if( bin!=null)
            bin.close();
      }
   }

   /** Check: Trimming a byte array should remove all leading zeroes */
   public void testArrayTrim() throws Exception {
      byte[] data1 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x07 };
      byte[] data2 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 };
      byte[] data3 = new byte[] { 0x00, 0x7A, 0x00, 0x00, 0x00 };
      byte[] data4 = new byte[] { 0x10, 0x7A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
      
      assertEquals("Array length", 1, CVCObject.trimByteArray(data1).length);
      assertEquals("Array length", 1, CVCObject.trimByteArray(data2).length);
      assertEquals("Array length", 4, CVCObject.trimByteArray(data3).length);
      assertEquals("Array length", 10, CVCObject.trimByteArray(data4).length);
   }


   /** Check: Decoding of AuthorizationField  */
   public void testAuthorizationField() throws Exception {
      AuthorizationField auth1 = new AuthorizationField(new byte[] {(byte) 0xC3});  // This means CVCA/DG3+DG4
      assertEquals(AuthorizationRoleEnum.CVCA, auth1.getRole());
      assertEquals(AccessRightEnum.READ_ACCESS_DG3_AND_DG4, auth1.getAccessRight());

      AuthorizationField auth2 = new AuthorizationField(new byte[] {(byte) 0x42});  // This means CV-f/DG4
      assertEquals(AuthorizationRoleEnum.DV_F, auth2.getRole());
      assertEquals(AccessRightEnum.READ_ACCESS_DG4, auth2.getAccessRight());
   }

   
   /** Check: Encoding/decoding of a HolderReference should not affect its data */ 
   public void testHolderReference() throws Exception {
      try {
         new HolderReferenceField("",HR_HOLDER_MNEMONIC,HR_SEQUENCE_NO);
         throw new Exception("Empty countryCode should throw IllegalArgumentException!");
      }
      catch( IllegalArgumentException e ){
         // This is expected
      }

      try {
         new HolderReferenceField("SWE",HR_HOLDER_MNEMONIC,HR_SEQUENCE_NO);
         throw new Exception("Too long countryCode should throw IllegalArgumentException!");
      }
      catch( IllegalArgumentException e ){
         // This is expected
      }

      try {
         new HolderReferenceField(HR_COUNTRY_CODE,"",HR_SEQUENCE_NO);
         throw new Exception("Empty mnemonic should throw IllegalArgumentException!");
      }
      catch( IllegalArgumentException e ){
         // This is expected
      }

      try {
         new HolderReferenceField(HR_COUNTRY_CODE,HR_HOLDER_MNEMONIC,"");
         throw new Exception("Empty sequence should throw IllegalArgumentException!");
      }
      catch( IllegalArgumentException e ){
         // This is expected
      }

      HolderReferenceField holderRef = new HolderReferenceField(HR_COUNTRY_CODE,HR_HOLDER_MNEMONIC,HR_SEQUENCE_NO);
      byte[] der = holderRef.getEncoded();
      
      HolderReferenceField holderRef2 = new HolderReferenceField(der);

      assertEquals(HR_COUNTRY_CODE,    holderRef2.getCountry());
      assertEquals(HR_HOLDER_MNEMONIC, holderRef2.getMnemonic());
      assertEquals(HR_SEQUENCE_NO,     holderRef2.getSequence());
      assertEquals(HR_COUNTRY_CODE+HR_HOLDER_MNEMONIC+HR_SEQUENCE_NO, holderRef2.getConcatenated());
   }
 

   /** Check: Validate IntegerField */
   public void testIntegerField() throws Exception {
      try {
         new IntegerField(CVCTagEnum.PROFILE_IDENTIFIER, new byte[]{ 1,2,3,4,5 });
         throw new Exception("Too long byte array should throw IllegalArgumentException");
      }
      catch( IllegalArgumentException e ){
         // This is expected
      }
      IntegerField intField = new IntegerField(CVCTagEnum.PROFILE_IDENTIFIER, new byte[]{ (byte)0xA0, (byte)0xA0 });
      assertEquals("Decoced int", 41120, intField.getValue());
   }


   /** Check: Encoding/decoding of a DateField should not affect its data */
   public void testDateField() throws Exception {
      Calendar cal1 = Calendar.getInstance();
      cal1.set(Calendar.YEAR, 2011);
      cal1.set(Calendar.MONTH, 0);   // This should generate a '1' in the byte array
      cal1.set(Calendar.DAY_OF_MONTH, 31);
      String s1 = FORMAT_PRINTABLE.format(cal1.getTime());

      DateField date1 = new DateField(CVCTagEnum.EFFECTIVE_DATE, cal1.getTime());
      byte[] enc = date1.getEncoded();
      
      // Reference: Every figure is stored in its own byte
      byte[] dateRef = new byte[] { 0x01, 0x01, 0x00, 0x01, 0x03, 0x01 };
      
      // Compare byte by byte
      assertTrue("Byte arrays not equal", Arrays.equals(enc, dateRef));

      // Compare strings to avoid problems with seconds etc
      DateField date2 = new DateField(CVCTagEnum.EFFECTIVE_DATE, enc);
      Calendar cal2 = Calendar.getInstance();
      cal2.setTime(date2.getDate());
      String s2 = FORMAT_PRINTABLE.format(cal2.getTime());
      assertEquals(s1, s2);
   }

 
   /** Check: Encoding of the OID field */
   public void testOIDField() throws Exception {
      String oidValue = "1.2.3";
      OIDField oid1 = new OIDField(oidValue);
      byte[] der = oid1.getEncoded();
      
      // First two numbers in the OID are encoded as 40*i1 + i2, the rest as i3, i4, ...
      byte[] oidRef = new byte[] { 0x2A, 0x03 };
      
      assertTrue("Byte arrays not equal", Arrays.equals(der,oidRef));

      OIDField oid2 = new OIDField(der);
      assertEquals("Parsed oid not equal", oidValue, oid2.getValue());
   }
   
}
