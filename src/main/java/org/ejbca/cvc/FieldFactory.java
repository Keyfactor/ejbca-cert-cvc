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
 * Fabrik f�r att skapa instanser av AbstractDataField fr�n en tag.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class FieldFactory {

   /**
    * Skapar instans som motsvarar angiven tag, samt populerar objektet med DER-kodat data.
    * @param tag
    * @param data
    * @return
    * @throws IOException
    * @throws IllegalArgumentException om angiven tag motsvarar en sequence
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
