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

/**
 * Klassen representerar ett integer-f�lt
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class IntegerField
      extends AbstractDataField {

   private int intValue;


   /**
    * Skapar instans fr�n tagg och int-v�rde
    * @param tag
    * @param value
    */
   IntegerField(CVCTagEnum tag, int value) {
      super(tag);
      this.intValue = value;
   }

   /**
    * Skapar instans fr�n tagg och bytearray. Obs att om arrayens l�ngd 
    * �verstiger 4 (antal bytes i en int) s� kastas IllegalArgumentException.
    * @param tag
    * @param data
    */
   IntegerField(CVCTagEnum tag, byte[] data) {
      super(tag);
      if( data!=null && data.length>4 ){
         throw new IllegalArgumentException("Byte array too long, max is 4, was " + data.length);
      }
      this.intValue = new BigInteger(1, data).intValue();
   }

   public void setValue(int intValue){
      this.intValue = intValue;
   }

   public int getValue(){
      return intValue;
   }

   @Override
   protected byte[] getEncoded() {
      return toByteArray(intValue);
   }

   @Override
   protected String valueAsText() {
      return "" + intValue;
   }

}
