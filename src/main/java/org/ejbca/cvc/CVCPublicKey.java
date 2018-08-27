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

import java.io.IOException;
import java.security.PublicKey;

/**
 * Represents the sequence Public Key
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public abstract class CVCPublicKey
      extends AbstractSequence implements PublicKey {


   CVCPublicKey() {
      super(CVCTagEnum.PUBLIC_KEY);
   }

   // Implements java.security.PublicKey
   public byte[] getEncoded() {
      byte[] data = null;
      try {
         data = getDEREncoded();
      }
      catch (IOException e) {
         e.printStackTrace();
      }
      return data;
   }

   /**
    * Returns Object Identifier
    * @return
    */
   public OIDField getObjectIdentifier() throws NoSuchFieldException {
      return (OIDField)getSubfield(CVCTagEnum.OID);
   }

}
