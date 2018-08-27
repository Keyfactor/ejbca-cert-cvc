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
 * Definitions of roles for Signature Terminals in CVC.
 * 
 * @author Samuel Lidén Borell, PrimeKey Solutions AB
 * @version $Id$
 */
public enum AuthorizationRoleSignTermEnum implements AuthorizationRole {

   CVCA     (0xC0),
   /** DV (Accreditation Body) */
   DV_AB    (0x80),
   /** DV (Certification Service Provider) */ 
   DV_CSP   (0x40),
   /** Signature Terminal */
   SIGNTERM (0x00);

   
   private byte value;
   
   private AuthorizationRoleSignTermEnum(int value){
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
      return this == DV_AB || this == DV_CSP;
   }

   @Override
   public boolean isDomesticDV() {
      return false;
   }

   @Override
   public boolean isForeignDV() {
      return false;
   }

   @Override
   public boolean isAccreditationBodyDV() {
      return this == DV_AB;
   }

   @Override
   public boolean isCertificationServiceProviderDV() {
      return this == DV_CSP;
   }

   @Override
   public boolean isIS() {
      return false;
   }

   @Override
   public boolean isAuthenticationTerminal() {
      return false;
   }

   @Override
   public boolean isSignatureTerminal() {
      return this == SIGNTERM;
   }

   // Used by e.g. AuthorizationField.valueAsText()
   @Override
   public String toString() {
      switch (this) {
      case CVCA: return "CVCA";
      case DV_AB: return "DV-Accreditation-Body";
      case DV_CSP: return "DV-Certification-Service-Provider";
      case SIGNTERM: return "Signature-Terminal";
      }
      throw new IllegalStateException("Enum case not handled");
   }

}
