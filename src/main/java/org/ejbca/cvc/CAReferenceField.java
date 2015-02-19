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
 * Represents the CVC field 'Certificate Authority Reference'
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class CAReferenceField extends ReferenceField {

    private static final long serialVersionUID = 6311109644238677669L;

    /**
     * Constructs a new instance from separate fields
     * 
     * @param country
     *            - CountryCode according to ISO 3166-1 ALPHA-2
     * @param mnemonic
     *            - Holder Mnemonic (up to 9 characters)
     * @param seq
     *            - Sequence Number (exactly 5 alphanumeric characters)
     */
    public CAReferenceField(String country, String mnemonic, String seq) {
        super(CVCTagEnum.CA_REFERENCE, country, mnemonic, seq);
    }

    /**
     * Constructor for decoding DER-encoded data
     * 
     * @param data
     */
    public CAReferenceField(byte[] data) {
        super(CVCTagEnum.CA_REFERENCE, data);
    }

}
