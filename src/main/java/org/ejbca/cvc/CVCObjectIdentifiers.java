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
 * Object identifiers for the CVC library
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public interface CVCObjectIdentifiers {

   
//    From BSI Technical Guideline TR-03111:
//    bsi-de OBJECT IDENTIFIER ::= {
//      itu-t(0) identified-organization(4) etsi(0)
//      reserved(127) etsi-identified-organization(0) 7
//    }
    
//    From BSI Technical Guideline TR-03110:
//    id-TA OBJECT IDENTIFIER ::= {
//      bsi-de protocols(2) smartcard(2) 2
//    }
//
   static final String  bsi_de    = "0.4.0.127.0.7";
   static final String  id_TA     = bsi_de + ".2.2.2";
   static final String  id_TA_RSA = id_TA + ".1";

   public static final OIDField id_TA_RSA_v1_5_SHA_1    = new OIDField(id_TA_RSA + ".1");
   public static final OIDField id_TA_RSA_v1_5_SHA_256  = new OIDField(id_TA_RSA + ".2");
   public static final OIDField id_TA_RSA_v1_5_SHA_512  = new OIDField(id_TA_RSA + ".5");
   public static final OIDField id_TA_RSA_PSS_SHA_1     = new OIDField(id_TA_RSA + ".3");
   public static final OIDField id_TA_RSA_PSS_SHA_256   = new OIDField(id_TA_RSA + ".4");
   public static final OIDField id_TA_RSA_PSS_SHA_512   = new OIDField(id_TA_RSA + ".6");
   
   static final String id_TA_ECDSA = id_TA + ".2";
   public static final OIDField id_TA_ECDSA_SHA_1        = new OIDField(id_TA_ECDSA + ".1");
   public static final OIDField id_TA_ECDSA_SHA_224      = new OIDField(id_TA_ECDSA + ".2");
   public static final OIDField id_TA_ECDSA_SHA_256      = new OIDField(id_TA_ECDSA + ".3");
   public static final OIDField id_TA_ECDSA_SHA_384      = new OIDField(id_TA_ECDSA + ".4");
   public static final OIDField id_TA_ECDSA_SHA_512      = new OIDField(id_TA_ECDSA + ".5");


//  id-EAC-ePassport OBJECT IDENTIFIER ::= {
//      bsi-de applications(3) mrtd(1) roles(2) 1
//  }   
   public static final OIDField id_EAC_ePassport         = new OIDField(bsi_de + ".3.1.2.1");
   public static final OIDField id_EAC_roles_AT     = new OIDField(bsi_de + ".3.1.2.2");
   public static final OIDField id_EAC_roles_ST     = new OIDField(bsi_de + ".3.1.2.3");

}
