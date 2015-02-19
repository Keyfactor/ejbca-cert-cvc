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
 * Generic public key class that is only used while parsing DER-encoded data.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class GenericPublicKeyField extends AbstractSequence {

    private static final long serialVersionUID = 1L;
    // This declares all subfields that may be added to this Sequence.
    private static CVCTagEnum[] allowedFields = new CVCTagEnum[] { CVCTagEnum.OID, CVCTagEnum.MODULUS, CVCTagEnum.EXPONENT, CVCTagEnum.COEFFICIENT_A,
            CVCTagEnum.COEFFICIENT_B, CVCTagEnum.BASE_POINT_G, CVCTagEnum.BASE_POINT_R_ORDER, CVCTagEnum.PUBLIC_POINT_Y, CVCTagEnum.COFACTOR_F };

    @Override
    protected CVCTagEnum[] getAllowedFields() {
        return allowedFields;
    }

    GenericPublicKeyField() {
        super(CVCTagEnum.PUBLIC_KEY);
    }

}
