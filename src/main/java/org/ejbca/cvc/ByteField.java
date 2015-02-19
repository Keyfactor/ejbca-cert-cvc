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
 * Generic field representing binary data (or Octet String)
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class ByteField
      extends AbstractDataField {

    private static final long serialVersionUID = 1L;
    private byte[] data;
    private boolean showBitLength = false;

   /**
    * Constructor taking tag
    * @param tag
    */
   ByteField(CVCTagEnum tag) {
      super(tag);
   }

   /**
    * Constructor taking tag and data
    * @param tag
    * @param data
    */
   ByteField(CVCTagEnum tag, byte[] data) {
      this(tag, data, false);
   }

   /**
    * Constructor taking tag, data and flag indicating if data length should be
    * shown in valueAsText()
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
    * Returns flag for 'showBitLen'
    * @return
    */
   public boolean isShowBitLength() {
      return showBitLength;
   }

   /**
    * Sets flag 'showBitLen'
    * @param showBitLength - if true then valueAsText() will add an entry showing the length in bits
    */
   public void setShowBitLength(boolean showBitLength) {
      this.showBitLength = showBitLength;
   }

   /**
    * Returns the data.
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
      // Check if length in bits should be shown
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
