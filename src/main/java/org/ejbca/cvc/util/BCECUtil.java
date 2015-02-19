package org.ejbca.cvc.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Locale;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;

/** This is directly copied from org.bouncycastle.jce.provider.asymmetric.ec.Signature
 *  BC version 1.41b04 was the base of the copy-paste operation.
 *  
 * @version $Id$
 */
public final class BCECUtil
{
	/** private constructor this is a static utility class */
	private BCECUtil() {}
	
    public static byte[] convertX962SigToCVC(final String algorithmName, final byte[] xsig) throws IOException {
        // Only do this if it's an ECDSA algorithm
        if (!algorithmName.toUpperCase(Locale.getDefault()).contains("ECDSA")) {
            return xsig;
        }
        // Read r and s from asn.1 encoded x9.62 signature
        final ASN1InputStream aIn = new ASN1InputStream(xsig);
        final ASN1Sequence seq;
        try {
            seq = (ASN1Sequence) aIn.readObject();
        } finally {
            aIn.close();
        }
        final BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
        final BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();

        // Write r and s to not asn.1 encoded cvc signature
        final byte[] first = makeUnsigned(r);
        final byte[] second = makeUnsigned(s);
        byte[] res;

        if (first.length > second.length) {
            res = new byte[first.length * 2];
        } else {
            res = new byte[second.length * 2];
        }

        System.arraycopy(first, 0, res, res.length / 2 - first.length, first.length);
        System.arraycopy(second, 0, res, res.length - second.length, second.length);

        return res;

    }

	   public static byte[] convertCVCSigToX962(final String algorithmName, final byte[] xsig) throws SignatureException {
		   // Only do this if it's an ECDSA algorithm
		   if (!algorithmName.toUpperCase(Locale.getDefault()).contains("ECDSA")) {
			   return xsig;
		   }
		   // Read r and s from non asn.1 encoded CVC signature
           final byte[] first = new byte[xsig.length / 2];
           final byte[] second = new byte[xsig.length / 2];

           System.arraycopy(xsig, 0, first, 0, first.length);
           System.arraycopy(xsig, first.length, second, 0, second.length);

           final BigInteger r = new BigInteger(1, first);
           final BigInteger s = new BigInteger(1, second);

	       // Write r and s to asn.1 encoded X9.62 signature
           final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
           final DEROutputStream dOut = new DEROutputStream(bOut);
           final ASN1EncodableVector v = new ASN1EncodableVector();

           v.add(new ASN1Integer(r));
           v.add(new ASN1Integer(s));

           try {
               dOut.writeObject(new DERSequence(v));        	   
           } catch (IOException e) {
        	   throw new SignatureException(e);
           }

           return bOut.toByteArray();
	   }

	   private static byte[] makeUnsigned(final BigInteger val)
	   {
	       byte[] res = val.toByteArray();

	       if (res[0] == 0)
	       {
	           final byte[] tmp = new byte[res.length - 1];
	           System.arraycopy(res, 1, tmp, 0, tmp.length);
	           res = tmp;
	       }
	       return res;
	   }

}
