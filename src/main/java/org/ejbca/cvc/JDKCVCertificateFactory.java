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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.util.ArrayList;
import java.util.Collection;

import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;


/**
 * Class for dealing with CVC certificates.
 * <p>
 * At the moment this will deal with binary encoded CVC certificates. Only one CVC certificate can be in the input stream passed.
 * Bouncy Castle's JDKX509CertificateFactory was used as template for this class.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class JDKCVCertificateFactory
    extends CertificateFactorySpi
{

    private byte[] readBytes(InputStream in) throws IOException
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        int len = 0;
        byte[] buf = new byte[512];
        while ((len = in.read(buf)) > 0) {
            os.write(buf, 0, len);
        }
        in.close();
        os.close();

        return os.toByteArray();
    }

    /**
     * Generates a certificate object and initializes it with the data
     * read from the input stream inStream.
     */
    public Certificate engineGenerateCertificate(
        InputStream in) 
        throws CertificateException
    {
    	Certificate ret = null;
    	
        try {
        	byte[] certData = readBytes(in);
        	CVCertificate parsedObject = CertificateParser.parseCertificate(certData);
        	ret = new CardVerifiableCertificate(parsedObject);
        } catch (IOException e) {
            throw new CertificateException(e.toString());
        } catch (ParseException e) {
            throw new CertificateException(e.toString());
		} catch (ConstructionException e) {
            throw new CertificateException(e.toString());
		}
        return ret;
    }

    /**
     * Returns a (possibly empty) collection view of the certificate
     * read from the given input stream inStream.
     */
    public Collection<Certificate> engineGenerateCertificates(
        InputStream inStream) 
        throws CertificateException
    {
    	// CVC can only have one certificate in a stream
        Certificate     cert = engineGenerateCertificate(inStream);
        ArrayList<Certificate> certs = new ArrayList<Certificate>();
        certs.add(cert);

        return certs;
    }

    /** 
     * CRLs are not supported by CVC. Will always throw CRLException!
     */
    public CRL engineGenerateCRL(
        InputStream inStream) 
        throws CRLException
    {
    	throw new CRLException("CVC CertificateFactory can not create CRLs");
    }

    /** 
     * CRLs are not supported by CVC. Will always throw CRLException!
     */
    public Collection<CRL> engineGenerateCRLs(
        InputStream inStream) 
        throws CRLException
    {
    	throw new CRLException("CVC CertificateFactory can not create CRLs");
    }

}
