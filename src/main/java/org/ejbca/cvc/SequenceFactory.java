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
 * Fabrik f�r att skapa sekvenser, dvs objekt i certifikatet som inneh�ller andra objekt.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class SequenceFactory {

   /**
    * Skapar instans av AbstractSequence baserat p� angiven tag.
    * @param tag
    * @return
    * @throws IllegalArgumentException om angiven tag inte motsvarar en sequence
    */
   public static AbstractSequence createSequence(CVCTagEnum tag) {
      if( !tag.isSequence() ) {
         throw new IllegalArgumentException("Tag " + tag + " is not a sequence");
      }
      
      switch( tag ){
         case CV_CERTIFICATE       : return new CVCertificate();
         case CERTIFICATE_BODY     : return new CVCertificateBody();
         case PUBLIC_KEY           : return new GenericPublicKeyField();
         case HOLDER_AUTH_TEMPLATE : return new CVCAuthorizationTemplate();
         case REQ_AUTHENTICATION   : return new CVCAuthenticatedRequest();
      }
      throw new IllegalArgumentException("Unsupported type " + tag);
   }

}
