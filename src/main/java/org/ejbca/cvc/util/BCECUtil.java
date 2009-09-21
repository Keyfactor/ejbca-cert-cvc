package org.ejbca.cvc.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;

/** This is directly copied from org.bouncycastle.jce.provider.asymmetric.ec.Signature
 *  BC version 1.41b04 was the base of the copy-paste operation.
 *  
 * @version $Id$
 */
public class BCECUtil
{
	   public static byte[] convertX962SigToCVC(String algorithmName, byte[] xsig) throws IOException {
		   // Only do this if it's an ECDSA algorithm
		   if (!algorithmName.toUpperCase().contains("ECDSA")) {
			   return xsig;
		   }
		   // Read r and s from asn.1 encoded x9.62 signature
	       ASN1InputStream aIn = new ASN1InputStream(xsig);
	       ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
	       BigInteger r = ((DERInteger)seq.getObjectAt(0)).getValue();
	       BigInteger s = ((DERInteger)seq.getObjectAt(1)).getValue();

	       // Write r and s to not asn.1 encoded cvc signature
	       byte[] first = makeUnsigned(r);
	       byte[] second = makeUnsigned(s);
	       byte[] res;

	       if (first.length > second.length)
	       {
	           res = new byte[first.length * 2];
	       }
	       else
	       {
	           res = new byte[second.length * 2];
	       }

	       System.arraycopy(first, 0, res, res.length / 2 - first.length, first.length);
	       System.arraycopy(second, 0, res, res.length - second.length, second.length);

	       return res;
	   }

	   public static byte[] convertCVCSigToX962(String algorithmName, byte[] xsig) throws SignatureException {
		   // Only do this if it's an ECDSA algorithm
		   if (!algorithmName.toUpperCase().contains("ECDSA")) {
			   return xsig;
		   }
		   // Read r and s from non asn.1 encoded CVC signature
           byte[] first = new byte[xsig.length / 2];
           byte[] second = new byte[xsig.length / 2];

           System.arraycopy(xsig, 0, first, 0, first.length);
           System.arraycopy(xsig, first.length, second, 0, second.length);

           BigInteger r = new BigInteger(1, first);
           BigInteger s = new BigInteger(1, second);

	       // Write r and s to asn.1 encoded X9.62 signature
           ByteArrayOutputStream bOut = new ByteArrayOutputStream();
           DEROutputStream dOut = new DEROutputStream(bOut);
           ASN1EncodableVector v = new ASN1EncodableVector();

           v.add(new DERInteger(r));
           v.add(new DERInteger(s));

           try {
               dOut.writeObject(new DERSequence(v));        	   
           } catch (IOException e) {
        	   throw new SignatureException(e);
           }

           return bOut.toByteArray();
	   }

	   private static byte[] makeUnsigned(BigInteger val)
	   {
	       byte[] res = val.toByteArray();

	       if (res[0] == 0)
	       {
	           byte[] tmp = new byte[res.length - 1];

	           System.arraycopy(res, 1, tmp, 0, tmp.length);

	           return tmp;
	       }

	       return res;
	   }

}
