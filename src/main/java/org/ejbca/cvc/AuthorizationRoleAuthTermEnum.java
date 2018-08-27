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
 * Definitions of roles for Authentication Terminals in CVC.
 * 
 * @author Samuel Lidén Borell, PrimeKey Solutions AB
 * @version $Id$
 *
 */
public enum AuthorizationRoleAuthTermEnum implements AuthorizationRole {

   CVCA  (0xC0),
   /** DV (Domestic/official) */
   DV_D  (0x80),
   /** DV (Foreign/non-official) */
   DV_F  (0x40),
   /** Authentication Terminal */
   AUTHTERM (0x00);

   
   private byte value;
   
   private AuthorizationRoleAuthTermEnum(int value){
      this.value = (byte)value;
   }
   
   /**
    * Returns the value as a bitmap
    * @return
    */
   @Override
   public byte getValue(){
      return value;
   }

   @Override
   public boolean isCVCA() {
      return this == CVCA;
   }
   
   @Override
   public boolean isDV() {
      return this == DV_D || this == DV_F;
   }

   @Override
   public boolean isDomesticDV() {
      return this == DV_D;
   }

   @Override
   public boolean isForeignDV() {
      return this == DV_F;
   }

   @Override
   public boolean isAccreditationBodyDV() {
      return false;
   }

   @Override
   public boolean isCertificationServiceProviderDV() {
      return false;
   }

   @Override
   public boolean isIS() {
      return false;
   }

   @Override
   public boolean isAuthenticationTerminal() {
      return this == AUTHTERM;
   }

   @Override
   public boolean isSignatureTerminal() {
      return false;
   }

   // Used by e.g. AuthorizationField.valueAsText()
   @Override
   public String toString() {
      switch (this) {
      case CVCA: return "CVCA";
      case DV_D: return "DV-domestic";
      case DV_F: return "DV-foreign";
      case AUTHTERM: return "Authentication-Terminal";
      }
      throw new IllegalStateException("Enum case not handled");
   }

}
