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

import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.OIDField;

import junit.framework.TestCase;

/**
 * Tests AlgorithmUtil
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TestAlgorithmUtil 
   extends TestCase implements CVCTest {
   

   protected void setUp() throws Exception {
      super.setUp();
   }

   protected void tearDown() throws Exception {
      super.tearDown();
   }

   
   /** Check: Validate AlgorithmUtil */ 
   public void testAlgorithmUtil() throws Exception {
      String algorithmName1 = "SHA224withECDSA";
      OIDField oid = AlgorithmUtil.getOIDField(algorithmName1);
      assertEquals("OID values not equal", oid.getValue(), "0.4.0.127.0.7.2.2.2.2.2");
      
      String algorithmName2 = AlgorithmUtil.getAlgorithmName(oid);
      assertEquals("algorithm names not equal", algorithmName1.toUpperCase(), algorithmName2);
      
      try {
         AlgorithmUtil.getOIDField("NonExistingAlgorithm");
         throw new Exception("Illegal algorithm name should throw IllegalArgumentException");
      }
      catch( IllegalArgumentException e ){
         // This is expected
      }
      
   }

}
