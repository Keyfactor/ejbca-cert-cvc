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

import org.bouncycastle.util.encoders.Hex;

/**
 * Internal object representing an access rights value of an unknown type.
 * These objects should be replaced by AuthorizationField.fixEnumTypes
 * and should never occur outside of CERT-CVC.
 * 
 * @author Samuel Lidén Borell, PrimeKey Solutions AB
 */
public class AccessRightsRawValue implements AccessRights {

   private final byte[] bytes;

   public AccessRightsRawValue(byte[] bytes) {
      this.bytes = bytes;
   }

   @Override
   public byte[] getEncoded() {
      return bytes;
   }

   @Override
   public String name() {
      return "RAW_ACCESS_RIGHTS";
   }

   @Override
    public String toString()
    {
       return "AccessRightsRawValue(" + Hex.toHexString(bytes).toUpperCase() + ")";
    }
}
