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
 *  
 * @author Samuel Lidén Borell, PrimeKey Solutions AB
 * @version $Id$
 */
public interface AuthorizationRole {
   /** @return true if the certificate holder is a CVCA */
   boolean isCVCA();

   /** @return true if the certificate holder is any kind of Document Verifier */
   boolean isDV();

   /** @return true if the certificate holder is a Document Verifier (Domestic/Official) */
   boolean isDomesticDV();

   /** @return true if the certificate holder is a Document Verifier (Foreign/Non-official) */
   boolean isForeignDV();

   /** @return true if the certificate holder is a Document Verifier (Accreditation Body) */
   boolean isAccreditationBodyDV();

   /** @return true if the certificate holder is a Document Verifier (Certification Service Provider) */
   boolean isCertificationServiceProviderDV();

   /** @return true if the certificate holder is an Inspection System */
   boolean isIS();

   /** @return true if the certificate holder is an Authentication Terminal */
   boolean isAuthenticationTerminal();

   /** @return true if the certificate holder is a Signature Terminal */
   boolean isSignatureTerminal();


   /** @return the encoded bitmap value */
   byte getValue();

   /** @see Enum#name() */
   String name();
}
