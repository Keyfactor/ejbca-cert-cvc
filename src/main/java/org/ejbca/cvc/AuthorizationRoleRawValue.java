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
 * @version $Id$
 */
public class AuthorizationRoleRawValue implements AuthorizationRole {
   
   private static final String EXCEPTION_MSG = "Authorization Role object does not know its type/OID yet. This is a bug.";
   private final byte value;
   
   AuthorizationRoleRawValue(byte value) {
      this.value = value;
   }
   
   @Override
   public boolean isCVCA() {
      throw new IllegalStateException(EXCEPTION_MSG);
   }
   
   @Override
   public boolean isDV() {
      throw new IllegalStateException(EXCEPTION_MSG);
   }
   
   @Override
   public boolean isDomesticDV() {
      throw new IllegalStateException(EXCEPTION_MSG);
   }
   
   @Override
   public boolean isForeignDV() {
      throw new IllegalStateException(EXCEPTION_MSG);
   }
   
   @Override
   public boolean isAccreditationBodyDV() {
      throw new IllegalStateException(EXCEPTION_MSG);
   }
   
   @Override
   public boolean isCertificationServiceProviderDV() {
      throw new IllegalStateException(EXCEPTION_MSG);
   }
   
   @Override
   public boolean isIS() {
      throw new IllegalStateException(EXCEPTION_MSG);
   }
   
   @Override
   public boolean isAuthenticationTerminal() {
      throw new IllegalStateException(EXCEPTION_MSG);
   }
   
   @Override
   public boolean isSignatureTerminal() {
      throw new IllegalStateException(EXCEPTION_MSG);
   }
   
   @Override
   public byte getValue() {
      return value;
   }
   
   @Override
   public String name() {
      throw new IllegalStateException(EXCEPTION_MSG);
   }
   
}
