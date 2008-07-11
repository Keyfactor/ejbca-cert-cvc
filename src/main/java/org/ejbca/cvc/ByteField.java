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

import org.ejbca.cvc.util.StringConverter;


/**
 * Generellt f�lt f�r att lagra bin�rdata.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class ByteField
      extends AbstractDataField {

   private byte[] data;
   private boolean showBitLength = false;

   /**
    * Skapar instans med endast tagg
    * @param tag
    */
   ByteField(CVCTagEnum tag) {
      super(tag);
   }

   /**
    * Skapar instans med tagg och data
    * @param tag
    * @param data
    */
   ByteField(CVCTagEnum tag, byte[] data) {
      this(tag, data, false);
   }

   /**
    * Skapar instans d�r man �ven kan ange ifall bitl�ngd ska visas
    * vid utskrift till text.
    * @param tag
    * @param data
    * @param showBitLength
    */
   ByteField(CVCTagEnum tag, byte[] data, boolean showBitLength) {
      super(tag);
      this.data = data;
      this.showBitLength = showBitLength;
   }

   
   /**
    * Returnerar flagga f�r 'showBitLen'
    * @return
    */
   public boolean isShowBitLength() {
      return showBitLength;
   }

   public void setShowBitLength(boolean showBitLength) {
      this.showBitLength = showBitLength;
   }

   /**
    * Returnerar f�ltets data.
    * @return
    */
   public byte[] getData() {
      return data;
   }

   @Override
   protected byte[] getEncoded() {
      return data;
   }

   @Override
   protected String valueAsText() {
      String lenInfo = "";
      // Kolla om l�ngd i antal bitar ska visas
      if( showBitLength ){
         int bitLength = 0;
         if( data!=null ){
            BigInteger big = new BigInteger(1, data);
            bitLength = big.bitLength();
         }
         lenInfo = "[" + bitLength + "]  ";
      }
      return lenInfo + StringConverter.byteToHex(data);
   }

}
