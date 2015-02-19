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
 * Base class for Certificate Authority/Holder Reference. Since the only
 * difference between these two is the tag we can reuse code for them.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public abstract class ReferenceField extends AbstractDataField {

    private static final long serialVersionUID = 1L;
    private String country = null;
    private String mnemonic = null;
    private String sequence = null;

    /**
     * Constructs a new instance from separate fields
     * 
     * @param country
     *            - CountryCode according to ISO 3166-1 ALPHA-2 (2 characters)
     * @param mnemonic
     *            - Holder Mnemonic (up to 9 characters)
     * @param seq
     *            - Sequence Number (exactly 5 alphanumeric characters)
     */
    public ReferenceField(CVCTagEnum tag, String country, String mnemonic, String seq) {
        super(tag);

        if (country.length() != 2) {
            throw new IllegalArgumentException("Country code length must be 2, was " + country.length());
        }
        if (!isValidCountry(country)) {
            throw new IllegalArgumentException("Unknown country code: " + country);
        }
        if (mnemonic.length() == 0) {
            throw new IllegalArgumentException("Holder mnemonic too short, must have at least one character");
        }
        if (mnemonic.length() > 9) {
            throw new IllegalArgumentException("Holder mnemonic too long, max=9, was " + mnemonic.length());
        }
        if (seq.length() != 5) {
            throw new IllegalArgumentException("Sequence number must have length 5, was " + seq.length());
        }
        for (int i = 0; i < seq.length(); i++) {
            // Validate character types
            char c = seq.charAt(i);
            if (!Character.isLetterOrDigit(c)) {
                throw new IllegalArgumentException("Sequence number can only contain alphanumerics: " + seq);
            }
        }

        this.country = country;
        this.mnemonic = mnemonic;
        this.sequence = seq;
    }

    /**
     * Constructs a new instance by parsing DER-encoded data
     * 
     * @param tag
     * @param data
     */
    protected ReferenceField(CVCTagEnum tag, byte[] data) {
        super(tag);

        String dataStr = new String(data);
        this.country = dataStr.substring(0, 2); // Has always length = 2
        this.mnemonic = dataStr.substring(2, dataStr.length() - 5);
        this.sequence = dataStr.substring(dataStr.length() - 5); // Has always
                                                                 // length = 5
    }

    /**
     * Returns the value as a concatenation of country, mnemonic and sequence
     * 
     * @return
     */
    public String getConcatenated() {
        return country + mnemonic + sequence;
    }

    /**
     * Returns country
     * 
     * @return
     */
    public String getCountry() {
        return country;
    }

    /**
     * Returns mnemonic
     * 
     * @return
     */
    public String getMnemonic() {
        return mnemonic;
    }

    /**
     * Returns sequence
     * 
     * @return
     */
    public String getSequence() {
        return sequence;
    }

    @Override
    protected byte[] getEncoded() {
        return getConcatenated().getBytes();
    }

    private boolean okChar(char c) {
        return c >= 'A' && c <= 'Z';
    }

    // Validates country code according to ISO 3166. AR: Not anymore :-) Testing
    // needs "unusual" countries
    private boolean isValidCountry(String countryCode) {
        return okChar(countryCode.charAt(0)) && okChar(countryCode.charAt(1));

    }

    @Override
    public String valueAsText() {
        return country + "/" + mnemonic + "/" + sequence;
    }

}
