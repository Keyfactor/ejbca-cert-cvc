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

/**
 * Representerar Access Rights avseende 
 * l�sbeh�righet till datagrupperna DG3, DG4.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public enum AccessRightEnum {

   READ_ACCESS_NONE        (0x00),
   READ_ACCESS_DG3         (0x01),
   READ_ACCESS_DG4         (0x02),
   READ_ACCESS_DG3_AND_DG4 (0x03);

   
   private byte value;

   private AccessRightEnum(int value){
      this.value = (byte)value;
   }

   /**
    * Returnerar v�rdet som en bitmapp.
    * @return
    */
   public byte getValue(){
      return value;
   }

}
