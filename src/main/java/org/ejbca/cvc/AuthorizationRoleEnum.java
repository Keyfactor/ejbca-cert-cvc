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
 * Definitioner av roll som anges i CVC.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public enum AuthorizationRoleEnum {

   CVCA  (0xC0),
   DV_D  (0x80),
   DV_F  (0x40),
   IS    (0x00);

   
   private byte value;
   
   private AuthorizationRoleEnum(int value){
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
