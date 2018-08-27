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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;

/**
 * Base class for all objects in a CV-certificate
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public abstract class CVCObject implements Serializable {

   private static final long serialVersionUID = 1L;

   public static final int CVC_VERSION = 0;

   public static final String NEWLINE = System.getProperty("line.separator");
   
   private static final int INT_LENGTH  = 4;
   private static final int LONG_LENGTH = 8;
   

   final private CVCTagEnum tag;
   private AbstractSequence parent;

   /**
    * Constructor taking a tag
    * @param tag
    */
   public CVCObject(final CVCTagEnum tag){
      this.tag = tag;
   }

   /**
    * Returns the tag
    * @return
    */
   public CVCTagEnum getTag() {
      return tag;
   }

   /**
    * Returns parent, that is, the AbstractSequence that contains this object (if any)
    * @return
    */
   public AbstractSequence getParent() {
      return parent;
   }

   /**
    * Sets the parent
    * @param parent
    */
   public void setParent(final AbstractSequence parent) {
      this.parent = parent;
   }

   /**
    * Writes this object as a DER-encoded byte array to 'out'
    * @return number of written bytes
    */
   protected abstract int encode(DataOutputStream out) throws IOException;


   /**
    * DER-encodes field length according to ITU-T X.690.
    * @param lenValue
    * @return
    */
   protected static byte[] encodeLength(final int lenValue){
      byte lenBytes = 0;
      if( lenValue>0x7F ){
         // Assume that one byte is sufficient for representing the length
         lenBytes = 1;
         if( lenValue>0xFF ) {
            // No, two bytes is required (assuming that the length is always <= 65535)
            lenBytes = 2;
         }
      }
      final ByteBuffer bb = ByteBuffer.allocate(1 + lenBytes);
      if( lenBytes==0 ){
         // One byte is enough - write the length value directly
         bb.put(0, (byte)lenValue);
      }
      else {
         // First write down how many bytes the length value requires.
         // This is done by setting the MSB + bitmap representing the actual length
         bb.put(0, (byte)(0x80 + lenBytes));
         if( lenBytes==1 ) {
            bb.put(1, (byte)lenValue);
         }
         else {
            bb.putShort(1, (short)lenValue);
         }
      }
      return bb.array();
   }


   /**
    * Reads and decodes a DER-encoded length value
    * @param in
    * @return
    */
   protected static int decodeLength(final DataInputStream in) throws IOException {
      int lenBytes = 1;
      int length = 0;
      final int b1 = in.read();
      if( b1>0x7F ) {  // If the MSB is set then the number of bytes is stored here
         lenBytes = b1 & 0xF;
         if( lenBytes==1 ) {
            length = in.readUnsignedByte();
         }
         else {
            // Assumption: lenBytes = 2 (theoretically it could be longer but hardly in a CV-certificate)
            length = in.readShort();
         }
      }
      else {
         // No, the MSB wasn't set so the length can be read directly from the current byte
         length = b1;
      }
      return length;
   }
   
   /**
    * Converts an Integer to a trimmed byte array.
    * @param intVal
    * @return
    * @see #trimByteArray(byte[])
    */
   protected static byte[] toByteArray(final Integer intVal) {
      final ByteBuffer bb = ByteBuffer.allocate(INT_LENGTH);
      bb.putInt(intVal);
      return trimByteArray(bb.array());
   }

   /**
    * Converts a Long to a trimmed byte array.
    * @param longVal
    * @return
    * @see #trimByteArray(byte[])
    */
   protected static byte[] toByteArray(Long longVal) {
      final ByteBuffer bb = ByteBuffer.allocate(LONG_LENGTH);
      bb.putLong(longVal);
      return trimByteArray(bb.array());
   }

   /**
    * Trims a byte array meaning that leading bytes containing zeros have been removed. 
    * However, if 'longVal' is zero then the array contains one zero.
    * @param data
    * @return
    */
   protected static byte[] trimByteArray(byte[] data) {
      boolean numberFound = false;
      int pos = 0;
      // Locate the first position of a non-zero
      for( pos=0; pos<data.length; pos++ ){
         numberFound = data[pos] != 0;
         if ( numberFound ) {
            break;
         }
      }

      byte[] result = null;
      if ( numberFound ) {
          // Non-zero was found - remove leading zeroes
          result = new byte[data.length-pos];
          System.arraycopy(data, pos, result, 0, data.length-pos);
      } else {
          // Only zeroes were found - return one zero
          result = new byte[]{ 0x00 };
      }
      return result;
   }


   /**
    * Same as getAsText("", true). 
    * @return
    */
   public String getAsText() {
      return getAsText("", true);
   }

   /**
    * Same as getAsText("", boolean). 
    * @param showTagNo
    * @return
    */
   public String getAsText(boolean showTagNo) {
      return getAsText("", showTagNo);
   }

   /**
    * Same as  getAsText(String, true). 
    * @param tab
    * @return
    */
   public String getAsText(String tab) {
      return getAsText(tab, true);
   }

   /**
    * Creates a textual representation of this object's tag. Subclasses should
    * call this method and then concatenate with the textual representation of
    * the subclasses' value.
    * @param tab supply some whitespace if indentation is wanted
    * @param showTagNo if 'true' then the hex tag value is printed also
    * @return
    */
   public String getAsText(String tab, boolean showTagNo) {
      final StringBuffer sb = new StringBuffer();
      sb.append(tab);
      if( showTagNo ){
         // Creates the string [TAB]0xFF[SPACE]TAG_NAME[SPACE]
         sb.append(Integer.toHexString(getTag().getValue())).append(' ');
      }
      sb.append(getTag().name()).append("  ");
      return sb.toString();
   }

}
