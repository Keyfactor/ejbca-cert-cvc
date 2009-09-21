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

/**
 * Factory for creating instances of AbstractDataField from a tag.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class FieldFactory {

   /**
    * Constructs a new instance and populates it with data from the supplied
    * DER-encoded byte array.
    * @param tag
    * @param data
    * @return
    * @throws IOException
    * @throws IllegalArgumentException if the tag represents a sequence
    */
   public static AbstractDataField decodeField(CVCTagEnum tag, byte[] data) throws IOException {
      if( tag.isSequence() ) {
         throw new IllegalArgumentException("Tag " + tag + " is a sequence");
      }
      
      AbstractDataField fieldObject = null;
      switch( tag ){
         case EFFECTIVE_DATE         : fieldObject = new DateField(tag, data); break;
         case EXPIRATION_DATE        : fieldObject = new DateField(tag, data); break;
         case CA_REFERENCE           : fieldObject = new CAReferenceField(data); break;
         case HOLDER_REFERENCE       : fieldObject = new HolderReferenceField(data); break;
         case OID                    : fieldObject = new OIDField(data); break;
         case ROLE_AND_ACCESS_RIGHTS : fieldObject = new AuthorizationField(data); break;
         case PROFILE_IDENTIFIER     : fieldObject = new IntegerField(tag, data); break;
         case COFACTOR_F             : fieldObject = new IntegerField(tag, data); break;
         default                     : fieldObject = new ByteField(tag, data);
      }
      return fieldObject;
   }

}
