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

import java.util.Date;

import org.ejbca.cvc.exception.ConstructionException;


/**
 * Klassen representerar CertificateBody i CV Certificate.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class CVCertificateBody
      extends AbstractSequence {

   private static CVCTagEnum[] allowedFields = new CVCTagEnum[] {
      CVCTagEnum.PROFILE_IDENTIFIER, 
      CVCTagEnum.CA_REFERENCE,
      CVCTagEnum.PUBLIC_KEY,
      CVCTagEnum.HOLDER_REFERENCE,
      CVCTagEnum.HOLDER_AUTH_TEMPLATE,
      CVCTagEnum.EFFECTIVE_DATE,
      CVCTagEnum.EXPIRATION_DATE
   };

   @Override
   CVCTagEnum[] getAllowedFields() {
      return allowedFields;
   }

   /**
    * Skapar en tom instans
    */
   CVCertificateBody() {
      super(CVCTagEnum.CERTIFICATE_BODY);
   }

   /**
    * Skapar instans avsedd f�r CertificateRequest
    * @param authorityReference
    * @param publicKey
    * @param holderReference
    * @throws ConstructionException
    */
   public CVCertificateBody(
         CAReferenceField      authorityReference, 
         CVCPublicKey          publicKey, 
         HolderReferenceField  holderReference ) throws ConstructionException
   {
      this();

      // Validera att n�dv�ndiga f�lt �r satta
      if( authorityReference==null ){
         throw new IllegalArgumentException("authorityReference is null");
      }
      if( publicKey==null ){
         throw new IllegalArgumentException("publicKey is null");
      }
      if( holderReference==null ){
         throw new IllegalArgumentException("holderReference is null");
      }

      // L�gg till subf�lten
      addSubfield(new IntegerField(CVCTagEnum.PROFILE_IDENTIFIER, CVC_VERSION ));
      addSubfield(authorityReference);
      
      addSubfield(publicKey);
      addSubfield(holderReference);
   }

   /**
    * Skapar instans avsedd f�r Certificate
    * @param authorityReference
    * @param publicKey
    * @param holderReference
    * @param authRole
    * @param accessRight
    * @param validFrom
    * @param validTo
    */
   public CVCertificateBody(
         CAReferenceField      authorityReference, 
         CVCPublicKey          publicKey, 
         HolderReferenceField  holderReference, 
         AuthorizationRoleEnum authRole,
         AccessRightEnum       accessRight,
         Date                  validFrom,
         Date                  validTo) throws ConstructionException
   {
      this(authorityReference, publicKey, holderReference);

      if( authRole==null ){
         throw new IllegalArgumentException("authRole is null");
      }
      if( accessRight==null ){
         throw new IllegalArgumentException("accessRight is null");
      }
      if( validFrom==null ){
         throw new IllegalArgumentException("validFrom is null");
      }
      if( validTo==null ){
         throw new IllegalArgumentException("validTo is null");
      }
      

      addSubfield(new CVCAuthorizationTemplate(authRole, accessRight));
      addSubfield(new DateField(CVCTagEnum.EFFECTIVE_DATE,  validFrom));
      addSubfield(new DateField(CVCTagEnum.EXPIRATION_DATE, validTo));
   }

   /**
    * Returnerar CVCAuthorizationTemplate
    * @return
    */
   public CVCAuthorizationTemplate getAuthorizationTemplate() throws NoSuchFieldException {
      return (CVCAuthorizationTemplate)getSubfield(CVCTagEnum.HOLDER_AUTH_TEMPLATE);
   }

   /**
    * Returnerar 'Effective Date' 
    * @return
    */
   public Date getValidFrom() throws NoSuchFieldException {
      return ((DateField)getSubfield(CVCTagEnum.EFFECTIVE_DATE)).getDate();
   }

   /**
    * Returnerar 'Expiration Date' 
    * @return
    */
   public Date getValidTo() throws NoSuchFieldException {
      return ((DateField)getSubfield(CVCTagEnum.EXPIRATION_DATE)).getDate();
   }
   
   /**
    * Returnerar v�rdet f�r 'Certificate Authority Reference'
    * Eftersom f�ltet inte �r obligatoriskt i ett Request s� returneras null
    * om f�ltet saknas ist�llet f�r att kasta NoSuchFieldException.
    * @return
    */
   public CAReferenceField getAuthorityReference() throws NoSuchFieldException {
      return (CAReferenceField)getOptionalSubfield(CVCTagEnum.CA_REFERENCE);
   }

   /**
    * Returnerar publika nyckeln
    * @return
    */
   public CVCPublicKey getPublicKey() throws NoSuchFieldException {
      return (CVCPublicKey)getSubfield(CVCTagEnum.PUBLIC_KEY);
   }

   /**
    * Returnerar v�rdet f�r 'Certificate Holder Reference'
    * @return
    */
   public HolderReferenceField getHolderReference() throws NoSuchFieldException {
      return (HolderReferenceField)getSubfield(CVCTagEnum.HOLDER_REFERENCE);
   } 

}
