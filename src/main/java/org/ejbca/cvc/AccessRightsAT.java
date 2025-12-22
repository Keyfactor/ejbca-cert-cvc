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

import org.ejbca.cvc.util.StringConverter;
import java.util.Arrays;
import java.io.Serializable;

/**
 * Represents access rights for an IS, CVCA or DVCA as specified in "BSI
 * TR-03110-3 Advanced Security Mechanisms for Machine Readable Travel Documents
 * – Part 3 - Version 2.10".
 *
 * <p>
 * Access can be explicitly given to DG3 (Fingerprint) and DG4 (Iris) as well as
 * to 4 functions reserved for future use (RFU).
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @author Bastian Fredriksson, PrimeKey Solutions AB
 */
public class AccessRightsAT implements AccessRights, Serializable {

	private static final long serialVersionUID = 1L;

	private static final byte READ_ACCESS_DG22 = 0x1d;
	private static final byte WRITE_ACCESS_DG22 = 0x20;

	private byte value;

	/**
	 * Create a new instance of this object from a bitmap. Only the first 6 bits
	 * representing access rights are stored, the two leftmost bits are cleared if
	 * set.
	 *
	 * @param value a bitmap with access rights.
	 */
	public AccessRightsAT(final byte value) {
		this.value = (byte) (value & 0b00100000);
	}

	public static AccessRightsAT READ_ACCESS_DG22() {
		return new AccessRightsAT(READ_ACCESS_DG22);
	}

	public static AccessRightsAT WRITE_ACCESS_DG22() {
		return new AccessRightsAT(WRITE_ACCESS_DG22);
	}

	/**
	 * Returns the access rights as a bitmap as they should appear in the
	 * certificate. Only the first 6 bits define access rights.
	 *
	 * <p>
	 * See "BSI TR-03110-3 Advanced Security Mechanisms for Machine Readable Travel
	 * Documents – Part 3 - Version 2.10, Table 20: Authorization of Inspection
	 * Systems" for details.
	 *
	 * @return the access rights as a bitmap.
	 */
	public int getValue() {
		return value;
	}

	@Override
	public byte[] getEncoded() {
		return new byte[] { value };
	}

	@Override
	public String name() {
		return "ACCESS_RIGHT_AT_" + StringConverter.byteToHex(value);
	}
}
