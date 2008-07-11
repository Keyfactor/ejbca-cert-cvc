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
 * CVC:s implementation av ECPublicKey
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class PublicKeyEC
      extends CVCPublicKey implements ECPublicKey {
 
   /** V�rde f�r att indikera kodning av okomprimerad Point */
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

//   private String          objectIdentifier;
//   private ECParameterSpec ecParameterSpec;
//   private ECPoint         wPoint;   // 'Public point'

   
   @Override
   CVCTagEnum[] getAllowedFields() {
      return allowedFields;
   }

   
   /**
    * Skapar instans fr�n en GenericPublicKeyField
    * @param genericKey
    * @throws NoSuchFieldException
    */
   public PublicKeyEC(GenericPublicKeyField genericKey) throws ConstructionException, NoSuchFieldException {
      // Plocka ut alla f�lt som kan ing� i PublicKeyEC
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
    * Skapar instans fr�n en OIDField samt PublicKey
    * @param oid
    * @param pubKey
    */
   public PublicKeyEC(OIDField oid, ECPublicKey pubKeyEC) throws ConstructionException {
      super();

      addSubfield(oid);
      
      ECParameterSpec ecParameterSpec  = pubKeyEC.getParams();
      ECField ecField = ecParameterSpec.getCurve().getField();
      if( ecField instanceof ECFieldFp ){
         ECFieldFp fp = (ECFieldFp)ecField;
         addSubfield(new ByteField(CVCTagEnum.MODULUS,         trimByteArray(fp.getP().toByteArray())));
      }
      // TODO: Kan ecField vara av typen ECFieldF2m? Vad �r modulus d�??

      addSubfield(new ByteField(CVCTagEnum.COEFFICIENT_A,      trimByteArray(ecParameterSpec.getCurve().getA().toByteArray())));
      addSubfield(new ByteField(CVCTagEnum.COEFFICIENT_B,      trimByteArray(ecParameterSpec.getCurve().getB().toByteArray())));
      addSubfield(new ByteField(CVCTagEnum.BASE_POINT_G,       encodePoint(ecParameterSpec.getGenerator())));
      addSubfield(new ByteField(CVCTagEnum.BASE_POINT_R_ORDER, trimByteArray(ecParameterSpec.getOrder().toByteArray())));
      addSubfield(new ByteField(CVCTagEnum.PUBLIC_POINT_Y,     encodePoint(pubKeyEC.getW())));
      addSubfield(new IntegerField(CVCTagEnum.COFACTOR_F,      ecParameterSpec.getCofactor()));
   }


   /**
    * �verlagrad metod f�r att kunna styra vilka f�lt som ska med vi DER-kodning.
    * Enligt EAC Spec 1.11: 
    * CVCRequest m�ste ha alla parametrar, CVCA-cert _kan_ ha det, �vriga ska ej ha
    */
   @Override
   protected List<CVCObject> getEncodableFields() {
      try {
         ArrayList<CVCObject> list = new ArrayList<CVCObject>();
         // Denna �r alltid med
         list.add(getSubfield(CVCTagEnum.OID));
   
         boolean addParameters = false;
         
         // En f�rsta f�ruts�ttning �r att vi har en spec att utg� ifr�n
         ECParameterSpec ecParameterSpec = getParams();
         if( ecParameterSpec!=null ){
            AbstractSequence parent = getParent();
            if( parent!=null && (parent.getTag()==CVCTagEnum.CERTIFICATE_BODY) ){
               try {
                  CVCObject cvcObj = ((CVCertificateBody)parent).getOptionalSubfield(CVCTagEnum.HOLDER_AUTH_TEMPLATE);
                  if( cvcObj==null ){
                     // Ingen HOLDER_AUTH_TEMPLATE - Antagande: Det �r ett CVCRequest
                     addParameters = true;
                  }
                  else {
                     // HOLDER_AUTH_TEMPLATE finns, d� b�r det vara ett CVCertificate. Kolla rollen
                     AuthorizationField authField = ((CVCAuthorizationTemplate)cvcObj).getAuthorizationField();
                     addParameters = (authField!=null && authField.getRole()==AuthorizationRoleEnum.CVCA);
                  }
               }
               catch( NoSuchFieldException e ){
                  // Inget att g�ra
               }
            }
            else if( parent==null ){
               // Detta kan vara bra under utveckling - test att DER-koda bara sj�lva nyckeln
                addParameters = true;
            }
         }
         if( addParameters ){
            ECField ecField = ecParameterSpec.getCurve().getField();
            if( ecField instanceof ECFieldFp ){
               list.add(getSubfield(CVCTagEnum.MODULUS));
            }
            // TODO: Kan ecField vara av typen ECFieldF2m? Vad �r modulus d�??
   
            list.add(getSubfield(CVCTagEnum.COEFFICIENT_A));
            list.add(getSubfield(CVCTagEnum.COEFFICIENT_B));
            list.add(getSubfield(CVCTagEnum.BASE_POINT_G));
            list.add(getSubfield(CVCTagEnum.BASE_POINT_R_ORDER));
         }
         
         // Denna ska alltid med
         list.add(getSubfield(CVCTagEnum.PUBLIC_POINT_Y));
         
         if( addParameters ){
            list.add(getSubfield(CVCTagEnum.COFACTOR_F));
         }
         return list;
      }
      catch( NoSuchFieldException e ){
         // Instansen har inte skapats korrekt
         throw new IllegalStateException(e);
      }
   }


   public String getAlgorithm() {
      return "ECDSA";  // TODO: Kolla denna
   }


   public String getFormat() {
      return "CVC";  // TODO: Kolla denna
   }


   public ECParameterSpec getParams() {
      // Plocka fram subf�lten och  bygg upp spec-instansen i runtime
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
         // Instansen har inte skapats korrekt
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

      // Egentligen �r pointX.length = pointY.length
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
      
      return new ECPoint(new BigInteger(xEnc), new BigInteger(yEnc));
   }

}
