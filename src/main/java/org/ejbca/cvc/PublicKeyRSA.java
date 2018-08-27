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
import java.security.interfaces.RSAPublicKey;

import org.ejbca.cvc.exception.ConstructionException;

/**
 * Implements handling of a public key of RSA type.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class PublicKeyRSA extends CVCPublicKey implements RSAPublicKey {

    private static final long serialVersionUID = 1L;
    private static CVCTagEnum[] allowedFields = new CVCTagEnum[] { CVCTagEnum.OID, CVCTagEnum.MODULUS, CVCTagEnum.EXPONENT };

    @Override
    protected CVCTagEnum[] getAllowedFields() {
        return allowedFields;
    }

    /**
     * Constructs an instance from a GenericPublicKeyField
     * 
     * @param genericKey
     * @throws NoSuchFieldException
     */
    PublicKeyRSA(GenericPublicKeyField genericKey) throws ConstructionException, NoSuchFieldException {
        ByteField modulusField = (ByteField) genericKey.getSubfield(CVCTagEnum.MODULUS);
        modulusField.setShowBitLength(true); // We want to see this when
                                             // printing as text

        addSubfield(genericKey.getSubfield(CVCTagEnum.OID));
        addSubfield(modulusField);
        addSubfield(genericKey.getSubfield(CVCTagEnum.EXPONENT));
    }

    /**
     * Constructs an instance from OIDField and RSAPublicKey
     * 
     * @param oid
     * @param pubKey
     */
    PublicKeyRSA(OIDField oid, RSAPublicKey rsaKey) throws ConstructionException {
        super();

        addSubfield(oid);
        addSubfield(new ByteField(CVCTagEnum.MODULUS, trimByteArray(rsaKey.getModulus().toByteArray()), true));
        addSubfield(new ByteField(CVCTagEnum.EXPONENT, trimByteArray(rsaKey.getPublicExponent().toByteArray())));
    }

    public String getAlgorithm() {
        return "RSA";
    }

    public String getFormat() {
        return "CVC"; // TODO: This OK?
    }

    public BigInteger getPublicExponent() {
        try {
            ByteField exp = (ByteField) getSubfield(CVCTagEnum.EXPONENT);
            return new BigInteger(1, exp.getData());
        } catch (NoSuchFieldException e) {
            // This object has not been created correctly?
            throw new IllegalStateException(e);
        }
    }

    public BigInteger getModulus() {
        try {
            ByteField exp = (ByteField) getSubfield(CVCTagEnum.MODULUS);
            return new BigInteger(1, exp.getData());
        } catch (NoSuchFieldException e) {
            // This object has not been created correctly?
            throw new IllegalStateException(e);
        }
    }

}
