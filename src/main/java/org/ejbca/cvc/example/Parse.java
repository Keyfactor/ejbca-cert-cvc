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
package org.ejbca.cvc.example;

import java.io.File;

import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CertificateParser;


/**
 * Example code for parsing a DER-encoded byte array
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class Parse {


   public static void main(String[] args) {
      File file = new File("C:/cv_certs/mycert1.cvcert");
      
      try {
         byte[] certData = FileHelper.loadFile(file);
         CVCObject cvc = CertificateParser.parseCVCObject(certData);
         System.out.println(cvc.getAsText());
      }
      catch (Exception e) {
         e.printStackTrace();
      }
   }

}
