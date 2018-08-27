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
 * Represents the field Certificate Holder Reference.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class HolderReferenceField extends ReferenceField {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new instance from separate field values
     * 
     * @param country
     *            - CountryCode according to ISO 3166-1 ALPHA-2 (2 characters)
     * @param mnemonic
     *            - Holder Mnemonic (up to 9 characters)
     * @param seq
     *            - Sequence Number (exactly 5 alphanumeric characters)
     */
    public HolderReferenceField(String country, String mnemonic, String seq) {
        super(CVCTagEnum.HOLDER_REFERENCE, country, mnemonic, seq);
    }

    /**
     * Constructs a new instance by parsing DER-encoded data
     * 
     * @param data
     */
    public HolderReferenceField(byte[] data) {
        super(CVCTagEnum.HOLDER_REFERENCE, data);
    }

}
