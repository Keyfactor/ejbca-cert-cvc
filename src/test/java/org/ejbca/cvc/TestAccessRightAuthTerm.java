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

import junit.framework.TestCase;

/**
 * Tests the access rights mapping for Authentication Terminals (AT).
 * 
 * @author Andres Jakobs, Primekey AB
 */
public class TestAccessRightAuthTerm extends TestCase implements CVCTest {

	/** BSI TR-03110 v2.2 adds R-DG22 and W-DG22 */
	public void testFlagToStringBsiTr03110V2_2() {
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x01 }, "Age Verification");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x02 }, "Community ID Verification");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x04 }, "Restricted Identification");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x08 }, "Privileged Terminal");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x10 }, "CAN Allowed");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x20 }, "PIN Management");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x40 }, "Install Certificate");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x00, (byte) 0x80 }, "Install Qualified Certificate");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x01, 0x00 }, "R-DG1");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x02, 0x00 }, "R-DG2");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x04, 0x00 }, "R-DG3");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x08, 0x00 }, "R-DG4");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x10, 0x00 }, "R-DG5");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x20, 0x00 }, "R-DG6");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, 0x40, 0x00 }, "R-DG7");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x00, (byte) 0x80, 0x00 }, "R-DG8");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x01, 0x00, 0x00 }, "R-DG9");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x02, 0x00, 0x00 }, "R-DG10");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x04, 0x00, 0x00 }, "R-DG11");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x08, 0x00, 0x00 }, "R-DG12");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x10, 0x00, 0x00 }, "R-DG13");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x20, 0x00, 0x00 }, "R-DG14");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, 0x40, 0x00, 0x00 }, "R-DG15");
		testAccessRightsLabel(new byte[] { 0x00, 0x00, (byte) 0x80, 0x00, 0x00 }, "R-DG16");
		testAccessRightsLabel(new byte[] { 0x00, 0x01, 0x00, 0x00, 0x00 }, "R-DG17");
		testAccessRightsLabel(new byte[] { 0x00, 0x02, 0x00, 0x00, 0x00 }, "R-DG18");
		testAccessRightsLabel(new byte[] { 0x00, 0x04, 0x00, 0x00, 0x00 }, "R-DG19");
		testAccessRightsLabel(new byte[] { 0x00, 0x08, 0x00, 0x00, 0x00 }, "R-DG20");
		testAccessRightsLabel(new byte[] { 0x00, 0x10, 0x00, 0x00, 0x00 }, "R-DG21");
		testAccessRightsLabel(new byte[] { 0x00, 0x20, 0x00, 0x00, 0x00 }, "R-DG22");
		testAccessRightsLabel(new byte[] { 0x00, 0x40, 0x00, 0x00, 0x00 }, "RFU-30");
		testAccessRightsLabel(new byte[] { 0x00, (byte) 0x80, 0x00, 0x00, 0x00 }, "RFU-31");
		testAccessRightsLabel(new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00 }, "W-DG22");
		testAccessRightsLabel(new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00 }, "W-DG21");
		testAccessRightsLabel(new byte[] { 0x04, 0x00, 0x00, 0x00, 0x00 }, "W-DG20");
		testAccessRightsLabel(new byte[] { 0x08, 0x00, 0x00, 0x00, 0x00 }, "W-DG19");
		testAccessRightsLabel(new byte[] { 0x10, 0x00, 0x00, 0x00, 0x00 }, "W-DG18");
		testAccessRightsLabel(new byte[] { 0x20, 0x00, 0x00, 0x00, 0x00 }, "W-DG17");
		testAccessRightsLabel(new byte[] { 0x40, 0x00, 0x00, 0x00, 0x00 }, "");
		testAccessRightsLabel(new byte[] { (byte) 0x80, 0x00, 0x00, 0x00, 0x00 }, "");
	}
	
	private void testAccessRightsLabel(final byte[] accessRights, final String label) {
		assertEquals("Access rights do not match.", label, new AccessRightAuthTerm(accessRights).toString());
	}
}
