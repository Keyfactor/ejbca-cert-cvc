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

import java.io.File;
import java.security.PublicKey;
import java.security.Security;

import junit.framework.TestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.example.FileHelper;

/**
 * Tests CVCRequest with outer signature
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TestCVCRequestABSP
      extends TestCase implements CVCTest {


   protected void setUp() throws Exception {
      // Install Bouncy Castle as security provider 
      Security.addProvider(new BouncyCastleProvider());
   }

   protected void tearDown() throws Exception {
      // Uninstallera BC 
      Security.removeProvider("BC");
   }


   /** Check: OID should have been set to a specific value */
   public void testCVCRequestABSP() throws Exception {
	      byte[] bytes = FileHelper.loadFile(new File("./src/test/resources/absp.cvcert"));
	      CVCertificate cvc = (CVCertificate)CertificateParser.parseCVCObject(bytes);
	      PublicKey pk = cvc.getCertificateBody().getPublicKey();
	      bytes = FileHelper.loadFile(new File("./src/test/resources/absp.req"));
	      CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest)CertificateParser.parseCVCObject(bytes);
	      authreq.verify(pk);	      
   }


}
