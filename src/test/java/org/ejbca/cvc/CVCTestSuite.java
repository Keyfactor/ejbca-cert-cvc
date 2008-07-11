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

import junit.framework.Test;
import junit.framework.TestSuite;

/**
 * Skapar JUnit testsvit f�r alla testcase
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class CVCTestSuite {

   public static Test suite() {
      TestSuite suite = new TestSuite("Tester f�r CVC");
      
      suite.addTestSuite(TestAlgorithmUtil.class);
      suite.addTestSuite(TestFactories.class);
      suite.addTestSuite(TestDatafields.class);
      suite.addTestSuite(TestSequences.class);
      suite.addTestSuite(TestPublicKey.class);
      suite.addTestSuite(TestCVCRequest.class);
      suite.addTestSuite(TestCVCertificate.class);
      
      return suite;
   }

}
