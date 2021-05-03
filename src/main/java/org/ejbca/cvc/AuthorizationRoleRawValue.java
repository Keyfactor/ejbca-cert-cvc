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
 * Internal object representing a role value of an unknown type.
 * These objects should be replaced by AuthorizationField.fixEnumTypes
 * and should never occur outside of CERT-CVC.
 * 
 * @author Samuel Lidén Borell, PrimeKey Solutions AB
 */
public class AuthorizationRoleRawValue implements AuthorizationRole {
   
   private final byte value;
   
   public AuthorizationRoleRawValue(byte value) {
      this.value = value;
   }
   
   @Override
   public boolean isCVCA() {
      return false;
   }
   
   @Override
   public boolean isDV() {
       return false;
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
       return false;
   }
   
   @Override
   public boolean isSignatureTerminal() {
       return false;
   }
   
   @Override
   public byte getValue() {
      return value;
   }
   
   @Override
   public String name() {
      return "RAW_AUTHORIZATION_ROLE";
   }
   
   @Override
    public String toString()
    {
       return "AuthorizationRoleRawValue(" + Integer.toString( value & 0xFF, 16 ).toUpperCase() + ")";
    }
}
