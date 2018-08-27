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
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.ECPointUtil;
import org.ejbca.cvc.exception.ConstructionException;

/**
 * Implements handling of a public key of Elliptic Curve type.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class PublicKeyEC
      extends CVCPublicKey implements ECPublicKey {
 
   static final long serialVersionUID = 1L;  // TODO: Fix better value

   /** Byte value indicating the start of an uncompressed Point data array */
   public static final byte  UNCOMPRESSED_POINT_TAG = 0x04;

   private static CVCTagEnum[] allowedFields = new CVCTagEnum[] {
      CVCTagEnum.OID,
      CVCTagEnum.MODULUS, 
      CVCTagEnum.COEFFICIENT_A,
      CVCTagEnum.COEFFICIENT_B,
      CVCTagEnum.BASE_POINT_G,
      CVCTagEnum.BASE_POINT_R_ORDER,
      CVCTagEnum.PUBLIC_POINT_Y,
      CVCTagEnum.COFACTOR_F
   };
   

   @Override
   CVCTagEnum[] getAllowedFields() {
      return allowedFields;
   }

   
   /**
    * Creates an instance from a GenericPublicKeyField
    * @param genericKey
    * @throws NoSuchFieldException
    */
   public PublicKeyEC(GenericPublicKeyField genericKey) throws ConstructionException, NoSuchFieldException {
      // Copy all fields for a PublicKeyEC
      addSubfield(genericKey.getSubfield(CVCTagEnum.OID));
      addSubfield(genericKey.getOptionalSubfield(CVCTagEnum.MODULUS));
      addSubfield(genericKey.getOptionalSubfield(CVCTagEnum.COEFFICIENT_A));
      addSubfield(genericKey.getOptionalSubfield(CVCTagEnum.COEFFICIENT_B));
      addSubfield(genericKey.getOptionalSubfield(CVCTagEnum.BASE_POINT_G));
      addSubfield(genericKey.getOptionalSubfield(CVCTagEnum.BASE_POINT_R_ORDER));
      addSubfield(genericKey.getSubfield(CVCTagEnum.PUBLIC_POINT_Y));
      addSubfield(genericKey.getOptionalSubfield(CVCTagEnum.COFACTOR_F));
   }

   /**
    * Creates an instance from an OIDField and a java.security.interfaces.ECPublicKey
    * @param oid
    * @param pubKey
    * @param authRole role of certificate holder. If null or 'CVCA' all subfields are added,
    * otherwise only the required ones.
    */
   public PublicKeyEC(OIDField oid, ECPublicKey pubKeyEC, AuthorizationRoleEnum authRole) throws ConstructionException {
      super();

      addSubfield(oid);

      ECParameterSpec ecParameterSpec  = pubKeyEC.getParams();
      boolean addAllParams = (authRole==null || authRole==AuthorizationRoleEnum.CVCA);
      if( addAllParams ){
         ECField ecField = ecParameterSpec.getCurve().getField();
         if( ecField instanceof ECFieldFp ){
            ECFieldFp fp = (ECFieldFp)ecField;
            addSubfield(new ByteField(CVCTagEnum.MODULUS,         trimByteArray(fp.getP().toByteArray())));
         }
         // TODO: Can ecField be of type ECFieldF2m? Then what is the modulus?

         addSubfield(new ByteField(CVCTagEnum.COEFFICIENT_A,      trimByteArray(ecParameterSpec.getCurve().getA().toByteArray())));
         addSubfield(new ByteField(CVCTagEnum.COEFFICIENT_B,      trimByteArray(ecParameterSpec.getCurve().getB().toByteArray())));
         addSubfield(new ByteField(CVCTagEnum.BASE_POINT_G,       encodePoint(ecParameterSpec.getGenerator())));
         addSubfield(new ByteField(CVCTagEnum.BASE_POINT_R_ORDER, trimByteArray(ecParameterSpec.getOrder().toByteArray())));
      }

      addSubfield(new ByteField(CVCTagEnum.PUBLIC_POINT_Y,     encodePoint(pubKeyEC.getW())));

      if( addAllParams ){
         addSubfield(new IntegerField(CVCTagEnum.COFACTOR_F,      ecParameterSpec.getCofactor()));
      }
   }


   /**
    * Overridden method that enables us to control exactly which fields that are
    * included when DER-encoding.
    * According to EAC Spec 1.11: 
    * CVCRequest must contain all fields, CVCA-certificate may have all, others must 
    * only have the required fields.
    */
   @Override
   protected List<CVCObject> getEncodableFields() {
      try {
         ArrayList<CVCObject> list = new ArrayList<CVCObject>();
         // This field is always present
         list.add(getSubfield(CVCTagEnum.OID));
   
         boolean addAllParams = false;
         
         // First of all we must have an ECParameterSpec to read from
         ECParameterSpec ecParameterSpec = getParams();
         if( ecParameterSpec!=null ){
            AbstractSequence parent = getParent();
            if( parent!=null && (parent.getTag()==CVCTagEnum.CERTIFICATE_BODY) ){
               try {
                  CVCObject cvcObj = ((CVCertificateBody)parent).getOptionalSubfield(CVCTagEnum.HOLDER_AUTH_TEMPLATE);
                  if( cvcObj==null ){
                     // No HOLDER_AUTH_TEMPLATE - assumption: We're building a CVCRequest
                     addAllParams = true;
                  }
                  else {
                     // HOLDER_AUTH_TEMPLATE exists, so it should be a CVCertificate. Check if role is CVCA
                     AuthorizationField authField = ((CVCAuthorizationTemplate)cvcObj).getAuthorizationField();
                     addAllParams = (authField!=null && authField.getRole()==AuthorizationRoleEnum.CVCA);
                  }
               }
               catch( NoSuchFieldException e ){
                  // Nothing to do...
               }
            }
            else if( parent==null ){
               // This could be useful during development - enables DER-encoding of the public key alone
               addAllParams = true;
            }
         }
         if( addAllParams ){
            ECField ecField = ecParameterSpec.getCurve().getField();
            if( ecField instanceof ECFieldFp ){
               list.add(getSubfield(CVCTagEnum.MODULUS));
            }
            // TODO: Can ecField be of type ECFieldF2m? Then what is the modulus?
   
            list.add(getSubfield(CVCTagEnum.COEFFICIENT_A));
            list.add(getSubfield(CVCTagEnum.COEFFICIENT_B));
            list.add(getSubfield(CVCTagEnum.BASE_POINT_G));
            list.add(getSubfield(CVCTagEnum.BASE_POINT_R_ORDER));
         }
         
         // This field is always present
         list.add(getSubfield(CVCTagEnum.PUBLIC_POINT_Y));
         
         if( addAllParams ){
            list.add(getSubfield(CVCTagEnum.COFACTOR_F));
         }
         return list;
      }
      catch( NoSuchFieldException e ){
         // This instance has not been created correctly
         throw new IllegalStateException(e);
      }
   }


   public String getAlgorithm() {
      return "ECDSA";  // TODO: This OK?
   }


   public String getFormat() {
      return "CVC";  // TODO: This OK?
   }


   public ECParameterSpec getParams() {
      // Fetch the subfields and construct the ECParameterSpec
      ECParameterSpec ecParameterSpec = null;
      ByteField modulus       = (ByteField)getOptionalSubfield(CVCTagEnum.MODULUS);
      ByteField coefficient_a = (ByteField)getOptionalSubfield(CVCTagEnum.COEFFICIENT_A);
      ByteField coefficient_b = (ByteField)getOptionalSubfield(CVCTagEnum.COEFFICIENT_B);
      ByteField base_point_g  = (ByteField)getOptionalSubfield(CVCTagEnum.BASE_POINT_G);
      ByteField point_r_order = (ByteField)getOptionalSubfield(CVCTagEnum.BASE_POINT_R_ORDER);
      IntegerField cofactor   = (IntegerField)getOptionalSubfield(CVCTagEnum.COFACTOR_F);
      
      if( modulus!=null ){
         EllipticCurve curve = new EllipticCurve(
               // ECField2m ?
               new ECFieldFp(new BigInteger(1, modulus.getData())), // q
               new BigInteger(1, coefficient_a.getData()),  // a
               new BigInteger(1, coefficient_b.getData())); // b
   
         ecParameterSpec = new ECParameterSpec(
               curve,
               ECPointUtil.decodePoint(curve, base_point_g.getData()), // G
               new BigInteger(1, point_r_order.getData()), // n
               cofactor.getValue()); // h

      }
      return ecParameterSpec;
   }


   public ECPoint getW() {
      try {
         ByteField public_point_y = (ByteField)getSubfield(CVCTagEnum.PUBLIC_POINT_Y);
         return decodePoint(public_point_y.getData());
      }
      catch( NoSuchFieldException e ){
          // This instance has not been created correctly
         throw new IllegalStateException(e);
      }
   }

   /**
    * Uncompressed encoding of a ECPoint according to BSI-TR-03111 chapter 3.1.1:
    * 0x04 || enc(X) || enc(Y)
    * @param ecPoint
    * @return
    */
   public static byte[] encodePoint(ECPoint ecPoint) {
      byte[] pointX = trimByteArray(ecPoint.getAffineX().toByteArray());
      byte[] pointY = trimByteArray(ecPoint.getAffineY().toByteArray());

      // pointX.length should be equal to pointY.length...
      byte[] encoded = new byte[1 + pointX.length + pointY.length];
      encoded[0] = UNCOMPRESSED_POINT_TAG;
      System.arraycopy(pointX, 0, encoded, 1, pointX.length);
      System.arraycopy(pointY, 0, encoded, 1+pointX.length, pointY.length);

      return encoded;
   }

   /**
    * Decodes an uncompressed ECPoint. First byte must be 0x04, otherwise
    * IllegalArgumentException is thrown.
    * @param data
    * @return
    */
   public static ECPoint decodePoint(byte[] data) {
      if( data[0] != UNCOMPRESSED_POINT_TAG ){
         throw new IllegalArgumentException("First byte must be 0x" + UNCOMPRESSED_POINT_TAG);
      }
      byte[] xEnc = new byte[(data.length - 1) / 2];
      byte[] yEnc = new byte[(data.length - 1) / 2];

      System.arraycopy(data, 1, xEnc, 0, xEnc.length);
      System.arraycopy(data, xEnc.length + 1, yEnc, 0, yEnc.length);
      
      return new ECPoint(new BigInteger(1, xEnc), new BigInteger(1, yEnc));
   }

}
