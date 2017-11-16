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
 * Factory for creating sequences, that is certificate objects containing
 * subfields
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 * 
 */
public class SequenceFactory {

    /**
     * Constructs a new instance of a subclass to AbstractSequence
     * 
     * @param tag
     * @return
     * @throws IllegalArgumentException
     *             if the supplied tag does not represent a sequence
     */
    public static AbstractSequence createSequence(CVCTagEnum tag) {
        if (!tag.isSequence()) {
            throw new IllegalArgumentException("Tag " + tag + " is not a sequence");
        }

        switch (tag) {
        case CV_CERTIFICATE:
            return new CVCertificate();
        case CERTIFICATE_BODY:
            return new CVCertificateBody();
        case PUBLIC_KEY:
            return new GenericPublicKeyField();
        case HOLDER_AUTH_TEMPLATE:
            return new CVCAuthorizationTemplate();
        case REQ_AUTHENTICATION:
            return new CVCAuthenticatedRequest();
        case CERTIFICATE_EXTENSIONS:
            return new CVCertificateExtensions();
        case DISCRETIONARY_DATA_TEMPLATE:
            return new CVCDiscretionaryDataTemplate();
        default:
        }
        throw new IllegalArgumentException("Unsupported type " + tag);
    }

}
