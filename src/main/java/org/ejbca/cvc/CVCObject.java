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
 * Basklass f�r alla objekt i ett CV-certifikat (dataf�lt och sekvenser)
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public abstract class CVCObject 
   implements Serializable {

   public static final int CVC_VERSION = 0;

   public static final String NEWLINE = System.getProperty("line.separator");
   
   private static final int INT_LENGTH  = 4;
   private static final int LONG_LENGTH = 8;
   

   private CVCTagEnum tag;
   private AbstractSequence parent;

   /**
    * Konstruktor
    * @param tag
    */
   public CVCObject(CVCTagEnum tag){
      this.tag = tag;
   }

   /**
    * Returnerar objektets tagg
    * @return
    */
   public CVCTagEnum getTag() {
      return tag;
   }

   /**
    * Returnerar parent, dvs den Sequence som objeketet �r underordnad
    * @return
    */
   public AbstractSequence getParent() {
      return parent;
   }

   /**
    * S�tter parent
    * @param parent
    */
   public void setParent(AbstractSequence parent) {
      this.parent = parent;
   }

   /**
    * Skriver objektet som en DER-kodad byte-array till 'out'
    * @return Antal skrivna bytes
    */
   protected abstract int encode(DataOutputStream out) throws IOException;


   /**
    * DER-kodning f�r l�ngd enligt specifikationen f�r ITU-T X.690.
    * @param lenValue
    * @return
    */
   protected static byte[] encodeLength(int lenValue){
      byte lenBytes = 0;
      if( lenValue>0x7F ){
         // Antag f�rst att en byte r�cker f�r l�ngden
         lenBytes = 1;
         if( lenValue>0xFF ) {
            // Nej, tv� bytes kr�vs f�r att representera l�ngden.
            // Obs att vi f�ruts�tter att l�ngden aldrig �r > 65535
            lenBytes = 2;
         }
      }
      ByteBuffer bb = ByteBuffer.allocate(1 + lenBytes);
      if( lenBytes==0 ){
         // V�rdet var s� litet att ingen l�ngdindikering beh�vs - skriv v�rdet direkt
         bb.put(0, (byte)lenValue);
      }
      else {
         // H�r kr�vs en indikering p� hur m�nga bytes l�ngden skrivits i.
         // Det g�rs genom att s�tta h�gsta biten + bitar som motsvarar antal bytes.
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
    * L�ser och avkodar DER-kodad l�ngd
    * @param in
    * @return
    */
   protected static int decodeLength(DataInputStream in) throws IOException {
      int lenBytes = 1;
      int length = 0;
      int b1 = in.read();
      if( b1>0x7F ) {  // Om bit 8 �r satt s� finns info om antal bytes h�r
         lenBytes = b1 & 0xF;
         if( lenBytes==1 ) {
            length = in.readUnsignedByte();
         }
         else {
            // Underf�rst�tt: lenBytes = 2 (kan teoriskt vara l�ngre men knappast i CVC-cert)
            length = in.readShort();
         }
      }
      else {
         // Nej, bit 8 var inte satt s� l�ngden st�r direkt i denna byte
         length = b1;
      }
      return length;
   }
   
   /**
    * Ger en trimmad byte-array s� tillvida att inledande nollor
    * tas bort. Om val = 0 s� returneras en nolla.
    * @param val
    * @return
    */
   protected static byte[] toByteArray(Integer intVal) {
      ByteBuffer bb = ByteBuffer.allocate(INT_LENGTH);
      bb.putInt(intVal);
      return trimByteArray(bb.array());
   }

   /**
    * Ger en trimmad byte-array s� tillvida att inledande nollor
    * tas bort. Om val = 0 s� returneras en nolla.
    * @param val
    * @return
    */
   protected static byte[] toByteArray(Long intVal) {
      ByteBuffer bb = ByteBuffer.allocate(LONG_LENGTH);
      bb.putLong(intVal);
      return trimByteArray(bb.array());
   }

   /**
    * Ger en trimmad byte-array s� tillvida att inledande nollor
    * tas bort. Om 'data' endast inneh�ller nollor s� returneras 
    * dock en byte 0x00.
    * @param val
    * @return
    */
   protected static byte[] trimByteArray(byte[] data) {
      boolean numberFound = false;
      int pos = 0;
      // Hitta f�rsta f�rekomst av icke-noll
      for( pos=0; pos<data.length; pos++ ){
         numberFound = data[pos] != 0;
         if( numberFound )
            break;
      }

      byte[] result = null;
      if( !numberFound ){
         // Det fanns endast nollor - returnera en nolla
         result = new byte[]{ 0x00 };
      }
      else {
         // Det fanns icke-nollor - ta bort ev. inledande
         result = new byte[data.length-pos];
         System.arraycopy(data, pos, result, 0, data.length-pos);
      }
      return result;
   }


   /**
    * Samma som getAsText("", true). 
    * @param tab
    * @return
    */
   public String getAsText() {
      return getAsText("", true);
   }

   /**
    * Samma som getAsText("", boolean). 
    * @param tab
    * @return
    */
   public String getAsText(boolean showTagNo) {
      return getAsText("", showTagNo);
   }

   /**
    * Samma som getAsText(String, true). 
    * @param tab
    * @return
    */
   public String getAsText(String tab) {
      return getAsText(tab, true);
   }

   /**
    * Skapar en textuell beskrivning av objektets tagg. Subklasser
    * b�r anropa denna och sedan konkatenera med utskrift av sj�lva datat.
    * @param tab ev indentering
    * @param showTagNo styr ifall taggv�rdet ska skrivas ut eller ej
    * @return
    */
   public String getAsText(String tab, boolean showTagNo) {
      StringBuffer sb = new StringBuffer();
      sb.append(tab);
      if( showTagNo ){
         // Denna skapar str�ngen [TAB]0xFF[SPACE]TAG_NAME[SPACE]
         sb.append(Integer.toHexString(getTag().getValue())).append(" ");
      }
      sb.append(getTag().name()).append("  ");
      return sb.toString();
   }

}
