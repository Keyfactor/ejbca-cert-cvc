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

import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;


/**
 * Class responsible for decoding a DER-encoded CVC object, like a
 * CVCertificate or any other instance of CVCObject. 
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public final class CertificateParser {

   // Only static methods...
   private CertificateParser(){
   }
   
   /**
    * Decodes a DER-encoded byte array containing any CVCObject
    * @param data
    * @return
    */
   public static CVCObject parseCVCObject(byte[] data) throws ParseException, ConstructionException {
      return decode(data, null);
   }


   /**
    * Decodes a DER-encoded byte array containing a CVCertificate
    * @param data
    * @return
    */
   public static CVCertificate parseCertificate(byte[] data) throws ParseException, ConstructionException {
      return (CVCertificate)decode(data, CVCTagEnum.CV_CERTIFICATE);
   }

   // Creates InputStreams and starts the decoding
   private static CVCObject decode(byte[] data, CVCTagEnum expectedTag) throws ParseException, ConstructionException {
      ByteArrayInputStream bin = null;
      try {
         try {
            bin = new ByteArrayInputStream(data);
            DataInputStream din = new DataInputStream(bin);
            return decode(din, expectedTag, null);
         }
         finally {
            if( bin!=null ){
               bin.close();
            }
         }
      }
      catch( IOException e ){
         throw new ParseException(e);
      }
   }

   // Performs the actual decoding
   private static CVCObject decode(DataInputStream din, CVCTagEnum expectedTag, CVCTagEnum tagIfAmbiguous) 
   throws IOException, ConstructionException, ParseException {
      // First chunk to decode is the tag
      int tagValue = decodeTag(din);
      CVCTagEnum tag = findTagFromValue(tagValue);

      // Validate the tag if a specific one was expected here
      if( expectedTag!=null && tag!=expectedTag ){
         throw new ParseException("Expected first tag " + expectedTag + " but found " + tag);
      }
      // Special handling for certain tags that have the same value, e.g. ARBITRARY_DATA and ROLE_AND_ACCESS_RIGHTS
      if (tagIfAmbiguous != null && tag.getValue() == tagIfAmbiguous.getValue()) {
          tag = tagIfAmbiguous;
      }

      // The second chunk to decode is the field length
      int length = CVCObject.decodeLength(din);

      if( tag.isSequence() ){
         // Save the position where data for this sequence ends
         int sequenceEnd = din.available() - length;

         // Create correct instance of AbstractSequence
         AbstractSequence sequence = SequenceFactory.createSequence(tag);
         
         // Add this sequence's subfields through recursion
         while( din.available() > sequenceEnd ) {
            // Special handling for ARBITRARY_DATA which has the same value as ROLE_AND_ACCESS_RIGHTS
            final CVCTagEnum nestedTagIfAmbiguous;
            switch (tag) {
            case DISCRETIONARY_DATA_TEMPLATE:
                nestedTagIfAmbiguous = CVCTagEnum.ARBITRARY_DATA;
                break;
            default:
                nestedTagIfAmbiguous = null;
            }
            sequence.addSubfield(decode(din, null, nestedTagIfAmbiguous));
         }
         // If we got a GenericPublicKeyField we must map this 
         // into an instance of CVCPublicKey before continuing
         if( sequence instanceof GenericPublicKeyField ){
            sequence = KeyFactory.createInstance((GenericPublicKeyField)sequence);
         }
         return sequence;
      }
      else {
         // OK, it's a data field so just parse it
         byte[] data = new byte[length];
         din.read(data, 0, length);
         return FieldFactory.decodeField(tag, data);
      }
   }

   

   /* Maps a tag value to a specific CVCTagEnum. Note that there
    * exists two tags with the same value (0x82)! In this case the
    * first of these (EXPONENT) will be returned.
    */
   private static CVCTagEnum findTagFromValue(int tagvalue) throws ParseException{
      CVCTagEnum wantedType = null;
      for( CVCTagEnum type : CVCTagEnum.values() ){
         if( type.getValue()==tagvalue ){
            wantedType = type;
            break;
         }
      }
      if( wantedType!=null ){
         return wantedType;
      }
      else {
         throw new ParseException("Unknown CVC tag value " + Integer.toHexString(tagvalue));
      }
   }
   
   /**
    * Reads a tag value from the input stream. Encoded according to ITU-T X.690
    * @param din
    * @return
    */
   private static int decodeTag(DataInputStream din) throws IOException {
      int tagValue = 0;
      int b1 = din.readUnsignedByte();
      if( (b1 & 0x1F) == 0x1F ){
         // There is another byte to read
         byte b2 = din.readByte();
         tagValue = (b1 << 8) + b2;
      }
      else {
         tagValue = b1;
      }
      return tagValue;
   }
  
}
