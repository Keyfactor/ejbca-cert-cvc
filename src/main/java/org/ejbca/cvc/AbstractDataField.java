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

	private static final long serialVersionUID = 1L;


/**
    * Constructor, must supply the tag
    * @param pType
    */
   public AbstractDataField(CVCTagEnum pType) {
      super(pType);
   }

   /**
    * Generates a DER-encoded byte array from this object
    * @return
    */
   protected abstract byte[] getEncoded();

   /**
    * Generates a DER-encoded byte array from this object, including tag and length
    * @param out to write to
    * @return number of bytes written
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
    * Returns this field as text
    */
   @Override
   public String getAsText(String tab, boolean showTagNo) {
      StringBuffer sb = new StringBuffer();
      // Concatenates CVCObject.getAsText() and this.valueAsText()
      sb.append(super.getAsText(tab, showTagNo)).append(valueAsText());
      return sb.toString();
   }


   /**
    * Returns this field's data as text
    * @return
    */
   protected abstract String valueAsText();
   
}
