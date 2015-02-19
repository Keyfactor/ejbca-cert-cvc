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

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * Represents Object Identifier
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 * 
 */
public class OIDField extends AbstractDataField {

    private static final long serialVersionUID = 5212215839749666908L;
    private String id;

    OIDField() {
        super(CVCTagEnum.OID);
    }

    /**
     * Constructs a new instance from a String (the oid value)
     * 
     * @param id
     */
    OIDField(String id) {
        this();
        this.id = id;
    }

    /**
     * Constructs a new instance by parsing DER-encoded data
     * 
     * @param data
     */
    OIDField(byte[] data) {
        this();
        // For BC 1.46/1.47
        // this.id = ASN1ObjectIdentifier.getInstance(new DERTaggedObject(true,
        // 0, new DEROctetString(data)), false).getId();
        // For BC 1.45
        // this.id = DERObjectIdentifier.getInstance(new
        // DEROctetString(data)).getId();

        // For all BC versions
        // Create an octet string, generate it's encoding and replace the tag at
        // the start with the object identifier tag. You could then recover the
        // OID
        // using ASN1Object.fromByteArray().
        // BC 1.47 changed to ASN1Primitive though, so no reason to keep BC 1.45
        // compatibility, since it will not work anyway.
        this.id = ASN1ObjectIdentifier.getInstance(new DERTaggedObject(true, 0, new DEROctetString(data)), false).getId();
    }

    public String getValue() {
        return id;
    }

    @Override
    protected byte[] getEncoded() {
        byte[] encoding = null;
        try {
            // This will give the entire field in encoded format (starting with
            // tag and length)
            byte[] derField = new ASN1ObjectIdentifier(id).getEncoded();

            // Skip the first two bytes, they will be added later. Note: In
            // theory, Length could
            // involve more than one byte, but for an OID it seems highly
            // unlikely.
            encoding = new byte[derField.length - 2];
            System.arraycopy(derField, 2, encoding, 0, encoding.length);
            return encoding;
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    protected String valueAsText() {
        return id;
    }

    public String toString() {
        return getValue();
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof OIDField) {
            return id.equals(((OIDField) other).getValue());
        } else {
            return false;
        }
    }

}
