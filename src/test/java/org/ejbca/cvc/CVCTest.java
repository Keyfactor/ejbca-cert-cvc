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

import java.text.DateFormat;
import java.text.SimpleDateFormat;

/**
 * A collection of constants.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public interface CVCTest {

   static String CA_COUNTRY_CODE    = "SE";
   static String CA_HOLDER_MNEMONIC = "CVCA-RPS";
   static String CA_SEQUENCE_NO     = "00111";

   static String HR_COUNTRY_CODE    = "SE";
   static String HR_HOLDER_MNEMONIC = "IS-ABSP08";
   static String HR_SEQUENCE_NO     = "SE801";


   static final DateFormat FORMAT_PRINTABLE    = new SimpleDateFormat("yyyy-MM-dd");

}
