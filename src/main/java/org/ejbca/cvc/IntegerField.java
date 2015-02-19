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

import java.math.BigInteger;

/**
 * Represents a generic field of type Integer
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class IntegerField extends AbstractDataField {

    private static final long serialVersionUID = 1L;
    private int intValue;

    /**
     * Constructs a new instance from a tag and an int
     * 
     * @param tag
     * @param value
     */
    IntegerField(CVCTagEnum tag, int value) {
        super(tag);
        this.intValue = value;
    }

    /**
     * Constructs a new instance by parsing DER-encoded data. If the length of
     * data is > 4 then IllegalArgumentException is thrown.
     * 
     * @param tag
     * @param data
     */
    IntegerField(CVCTagEnum tag, byte[] data) {
        super(tag);
        if (data != null && data.length > 4) {
            throw new IllegalArgumentException("Byte array too long, max is 4, was " + data.length);
        }
        this.intValue = new BigInteger(1, data).intValue();
    }

    public void setValue(int intValue) {
        this.intValue = intValue;
    }

    public int getValue() {
        return intValue;
    }

    @Override
    protected byte[] getEncoded() {
        return toByteArray(intValue);
    }

    @Override
    protected String valueAsText() {
        return "" + intValue;
    }

}
