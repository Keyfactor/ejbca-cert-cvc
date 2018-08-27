package org.ejbca.cvc.util;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;

/** This is directly copied from org.bouncycastle.jce.provider.EC5Util, with one additional method from org.bouncycastle.jce.provider.ECUtil
 *  BC version 1.40 was the base of the copy-paste operation.
 *  
 * @version $Id$
 */
public class BCECUtil
{
    static EllipticCurve convertCurve(
        ECCurve curve, 
        byte[]  seed)
    {
        if (curve instanceof ECCurve.Fp)
        {
            return new EllipticCurve(new ECFieldFp(((ECCurve.Fp)curve).getQ()), curve.getA().toBigInteger(), curve.getB().toBigInteger(), seed);
        }
        else
        {
            ECCurve.F2m curveF2m = (ECCurve.F2m)curve;
            int ks[];
            
            if (curveF2m.isTrinomial())
            {
                ks = new int[] { curveF2m.getK1() };
                
                return new EllipticCurve(new ECFieldF2m(curveF2m.getM(), ks), curve.getA().toBigInteger(), curve.getB().toBigInteger(), seed);
            }
            else
            {
                ks = new int[] { curveF2m.getK3(), curveF2m.getK2(), curveF2m.getK1() };
                
                return new EllipticCurve(new ECFieldF2m(curveF2m.getM(), ks), curve.getA().toBigInteger(), curve.getB().toBigInteger(), seed);
            } 
        }
    }

    static ECCurve convertCurve(
        EllipticCurve ec)
    {
        ECField field = ec.getField();
        BigInteger a = ec.getA();
        BigInteger b = ec.getB();

        if (field instanceof ECFieldFp)
        {
            return new ECCurve.Fp(((ECFieldFp)field).getP(), a, b);
        }
        else
        {
            ECFieldF2m fieldF2m = (ECFieldF2m)field;
            int m = fieldF2m.getM();
            int ks[] = convertMidTerms(fieldF2m.getMidTermsOfReductionPolynomial());
            return new ECCurve.F2m(m, ks[0], ks[1], ks[2], a, b); 
        }
    }

    static ECParameterSpec convertSpec(
        EllipticCurve ellipticCurve,
        org.bouncycastle.jce.spec.ECParameterSpec spec)
    {
        if (spec instanceof ECNamedCurveParameterSpec)
        {
            return new ECNamedCurveSpec(
                ((ECNamedCurveParameterSpec)spec).getName(),
                ellipticCurve,
                new ECPoint(
                    spec.getG().getX().toBigInteger(),
                    spec.getG().getY().toBigInteger()),
                spec.getN(),
                spec.getH());
        }
        else
        {
            return new ECParameterSpec(
                ellipticCurve,
                new ECPoint(
                    spec.getG().getX().toBigInteger(),
                    spec.getG().getY().toBigInteger()),
                spec.getN(),
                spec.getH().intValue());
        }
    }

    public static org.bouncycastle.jce.spec.ECParameterSpec convertSpec(
        ECParameterSpec ecSpec,
        boolean withCompression)
    {
        ECCurve curve = convertCurve(ecSpec.getCurve());

        return new org.bouncycastle.jce.spec.ECParameterSpec(
            curve,
            convertPoint(curve, ecSpec.getGenerator(), withCompression),
            ecSpec.getOrder(),
            BigInteger.valueOf(ecSpec.getCofactor()),
            ecSpec.getCurve().getSeed());
    }

    public static org.bouncycastle.math.ec.ECPoint convertPoint(
        ECParameterSpec ecSpec,
        ECPoint point,
        boolean withCompression)
    {
        return convertPoint(convertCurve(ecSpec.getCurve()), point, withCompression);
    }

    static org.bouncycastle.math.ec.ECPoint convertPoint(
        ECCurve curve,
        ECPoint point,
        boolean withCompression)
    {
        return curve.createPoint(point.getAffineX(), point.getAffineY(), withCompression);
    }
    
    /**
     * Returns a sorted array of middle terms of the reduction polynomial.
     * @param k The unsorted array of middle terms of the reduction polynomial
     * of length 1 or 3.
     * @return the sorted array of middle terms of the reduction polynomial.
     * This array always has length 3.
     */
    static int[] convertMidTerms(
        int[] k)
    {
        int[] res = new int[3];
        
        if (k.length == 1)
        {
            res[0] = k[0];
        }
        else
        {
            if (k.length != 3)
            {
                throw new IllegalArgumentException("Only Trinomials and pentanomials supported");
            }

            if (k[0] < k[1] && k[0] < k[2])
            {
                res[0] = k[0];
                if (k[1] < k[2])
                {
                    res[1] = k[1];
                    res[2] = k[2];
                }
                else
                {
                    res[1] = k[2];
                    res[2] = k[1];
                }
            }
            else if (k[1] < k[2])
            {
                res[0] = k[1];
                if (k[0] < k[2])
                {
                    res[1] = k[0];
                    res[2] = k[2];
                }
                else
                {
                    res[1] = k[2];
                    res[2] = k[0];
                }
            }
            else
            {
                res[0] = k[2];
                if (k[0] < k[1])
                {
                    res[1] = k[0];
                    res[2] = k[1];
                }
                else
                {
                    res[1] = k[1];
                    res[2] = k[0];
                }
            }
        }

        return res;
    }

}
