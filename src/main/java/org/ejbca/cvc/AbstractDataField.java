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

import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Represents a data field (difference from sequence is no sub fields).
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public abstract class AbstractDataField
      extends CVCObject {

   /**
    * Konstruktor, m�ste ange objektets tagg
    * @param pType
    */
   public AbstractDataField(CVCTagEnum pType) {
      super(pType);
   }

   /**
    * Genererar en DER-kodad bytearray av objektets data.
    * @return
    */
   protected abstract byte[] getEncoded();

   /**
    * Genererar en DER-kodad bytearray av objektet, inklusive tagg och l�ngd.
    * @param outstream att skriva till
    * @return antalet skrivna bytes
    */
   @Override
   protected int encode(DataOutputStream out) throws IOException {
      int s0 = out.size();
      out.write( toByteArray(getTag().getValue()) );
      
      byte[] databytes = getEncoded();
      int len = databytes.length;
      out.write( encodeLength(len) );
      out.write( databytes );
      return out.size()-s0;
   }


   /**
    * Returnerar f�ltet i textformat.
    */
   @Override
   public String getAsText(String tab, boolean showTagNo) {
      StringBuffer sb = new StringBuffer();
      // Denna konkatenerar str�ngen fr�n CVCObject med f�ltets data i textformat
      sb.append(super.getAsText(tab, showTagNo)).append(valueAsText());
      return sb.toString();
   }


   /**
    * Returnerar f�ltets data i textformat
    * @return
    */
   protected abstract String valueAsText();
   
}
