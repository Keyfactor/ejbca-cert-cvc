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
 * Klass f�r att avkoda en DER-kodad bytearray till ett CVCObject, t ex
 * CVCertificate eller godtyckligt CVCObject. 
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class CertificateParser {

   // Klassen ska inte instansieras
   private CertificateParser(){
   }
   
   /**
    * Avkodar DER-kodad byte-array inneh�llande godtyckligt CVCObject
    * @param data
    * @return
    */
   public static CVCObject parseCVCObject(byte[] data) throws ParseException, ConstructionException {
      return decode(data, null);
   }


   /**
    * Avkodar DER-kodad byte-array inneh�llande CVCertificate
    * @param data
    * @return
    */
   public static CVCertificate parseCertificate(byte[] data) throws ParseException, ConstructionException {
      return (CVCertificate)decode(data, CVCTagEnum.CV_CERTIFICATE);
   }

   /** Skapar InputStreams och startar avkodning */
   private static CVCObject decode(byte[] data, CVCTagEnum expectedTag) throws ParseException, ConstructionException {
      ByteArrayInputStream bin = null;
      try {
         try {
            bin = new ByteArrayInputStream(data);
            DataInputStream din = new DataInputStream(bin);
            return decode(din, expectedTag);
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

   /** Utf�r sj�lva avkodningen av DER-kodat data  */
   private static CVCObject decode(DataInputStream din, CVCTagEnum expectedTag) 
   throws IOException, ConstructionException {
      // Taggen m�ste avkodas, kan best� av en eller tv� bytes
      int tagValue = decodeTag(din);
      CVCTagEnum tag = findTagFromValue(tagValue);

      // Validera att den f�rsta taggen �r korrekt
      if( expectedTag!=null && tag!=expectedTag ){
         throw new IllegalArgumentException("Expected first tag " + expectedTag + " but found " + tag);
      }

      int length = CVCObject.decodeLength(din);

      if( tag.isSequence() ){
         // Spara position f�r n�r datat f�r denna sekvens tar slut
         int sequenceEnd = din.available() - length;

         // Skapa r�tt instans av AbstractSequence
         AbstractSequence sequence = SequenceFactory.createSequence(tag);
         
         // L�gg till subf�lt genom rekursion
         while( din.available() > sequenceEnd ) {
            sequence.addSubfield(decode(din, null));
         }
         // Om vi har f�tt en GenericPublicKeyField s� m�ste vi
         // skapa r�tt typ innan vi forts�tter
         if( sequence instanceof GenericPublicKeyField ){
            sequence = KeyFactory.createInstance((GenericPublicKeyField)sequence);
         }
         return sequence;
      }
      else {
         // L�s upp byte-arrayen 
         byte[] data = new byte[length];
         din.read(data, 0, length);
         // Skapa och populera objektet fr�n bytearray
         return FieldFactory.decodeField(tag, data);
      }
   }

   

   /* �vers�tter ett tag-v�rde till CVTag. Obs att det finns tv�
    * taggar med samma v�rde (0x82). Denna kommer returnera den 
    * f�rsta av dessa.
    */
   private static CVCTagEnum findTagFromValue(int tagvalue){
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
         throw new IllegalArgumentException("Unknown CVC tag value " + Integer.toHexString(tagvalue));
      }
   }
   
   /**
    * L�ser tag fr�n input stream. Kan lagrs som en eller tv� bytes
    * enligt kodning f�r ITU-T X.690
    * @param din
    * @return
    */
   private static int decodeTag(DataInputStream din) throws IOException {
      int tagValue = 0;
      int b1 = din.readUnsignedByte();
      if( (b1 & 0x1F) == 0x1F ){
         // Det finns en byte till att l�sa
         byte b2 = din.readByte();
         tagValue = (b1 << 8) + b2;
      }
      else {
         tagValue = b1;
      }
      return tagValue;
   }

   
}
