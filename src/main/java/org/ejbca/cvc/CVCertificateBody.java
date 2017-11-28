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

import java.util.Collection;
import java.util.Date;

import org.ejbca.cvc.exception.ConstructionException;


/**
 * Represents a CertificateBody
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class CVCertificateBody extends AbstractSequence {

   private static final long serialVersionUID = 1L;
	
   private static CVCTagEnum[] allowedFields = new CVCTagEnum[] {
      CVCTagEnum.PROFILE_IDENTIFIER, 
      CVCTagEnum.CA_REFERENCE,
      CVCTagEnum.PUBLIC_KEY,
      CVCTagEnum.HOLDER_REFERENCE,
      CVCTagEnum.HOLDER_AUTH_TEMPLATE,
      CVCTagEnum.EFFECTIVE_DATE,
      CVCTagEnum.EXPIRATION_DATE,
      CVCTagEnum.CERTIFICATE_EXTENSIONS
   };

   @Override
   protected CVCTagEnum[] getAllowedFields() {
      return allowedFields;
   }

   /**
    * Creates an empty instance
    */
   CVCertificateBody() {
      super(CVCTagEnum.CERTIFICATE_BODY);
   }

   /**
    * Creates an instance suitable for CertificateRequest
    */
   public CVCertificateBody(
         CAReferenceField      authorityReference, 
         CVCPublicKey          publicKey, 
         HolderReferenceField  holderReference) throws ConstructionException
   {
       this(authorityReference, publicKey, holderReference, null);
   }
   
   /**
    * Creates an instance suitable for CertificateRequest
    * @param authorityReference CA reference
    * @param publicKey Public key for new certificate.
    * @param holderReference Holder reference
    * @param extensions Certificate extensions, or null to exclude.
    * @throws ConstructionException
    */
   public CVCertificateBody(
         CAReferenceField      authorityReference, 
         CVCPublicKey          publicKey, 
         HolderReferenceField  holderReference,
         Collection<CVCDiscretionaryDataTemplate> extensions) throws ConstructionException
   {
      this();

      // All arguments must be set, except authorityReference which is
      // optional in requests
      if( publicKey==null ){
         throw new IllegalArgumentException("publicKey is null");
      }
      if( holderReference==null ){
         throw new IllegalArgumentException("holderReference is null");
      }

      // Add subfields
      addSubfield(new IntegerField(CVCTagEnum.PROFILE_IDENTIFIER, CVC_VERSION ));
      addSubfield(authorityReference);
      
      addSubfield(publicKey);
      addSubfield(holderReference);
      if (extensions != null) {
          addSubfield(new CVCertificateExtensions(extensions));
      }
   }

   /**
    * Creates an instance suitable for a CVCertificate
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
         AuthorizationRole     authRole,
         AccessRights          accessRight,
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
      
      // Add subfields
      addSubfield(new CVCAuthorizationTemplate(authRole, accessRight));
      addSubfield(new DateField(CVCTagEnum.EFFECTIVE_DATE,  validFrom));
      addSubfield(new DateField(CVCTagEnum.EXPIRATION_DATE, validTo));
   }
   
   /**
    * Creates an instance suitable for a CVCertificate. This seemingly redundant overloaded
    * constructor is for binary (.class file) backwards compatibility. It is NOT deprecated to
    * use these argument types.
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
      this(authorityReference, publicKey, holderReference, 
         (AuthorizationRole)authRole, (AccessRights)accessRight, validFrom, validTo);
   }

   /**
    * Returns CVCAuthorizationTemplate
    * @return
    */
   public CVCAuthorizationTemplate getAuthorizationTemplate() throws NoSuchFieldException {
      return (CVCAuthorizationTemplate)getSubfield(CVCTagEnum.HOLDER_AUTH_TEMPLATE);
   }
   
   /**
    * Creates an instance suitable for a CVCertificate
    * @param authorityReference Contains country code, holder mnemonic, and sequence number for the issuer.
    * @param publicKey Public key of holder.
    * @param holderReference Contains country code, holder mnemonic, and sequence number for the certificate holder.
    * @param authRole Authorization role, specifies whether the holder is a CVCA, domestic DVCA, foreign DVCA, or AT/ST/IS.
    * @param accessRight Access rights
    * @param validFrom Validity from
    * @param validTo Validity to
    * @param extensions Certificate extensions, or null to not add a "Certificate Extensions" object to the certificate.
    */
   public CVCertificateBody(
         CAReferenceField      authorityReference, 
         CVCPublicKey          publicKey, 
         HolderReferenceField  holderReference, 
         AuthorizationRole     authRole,
         AccessRights          accessRight,
         Date                  validFrom,
         Date                  validTo,
         Collection<CVCDiscretionaryDataTemplate> extensions) throws ConstructionException
   {
      this(authorityReference, publicKey, holderReference, authRole, accessRight, validFrom, validTo);
      if (extensions != null) {
          addSubfield(new CVCertificateExtensions(extensions));
      }
   }

   /**
    * Returns 'Effective Date' 
    * @return
    */
   public Date getValidFrom() throws NoSuchFieldException {
      return ((DateField)getSubfield(CVCTagEnum.EFFECTIVE_DATE)).getDate();
   }

   /**
    * Returns 'Expiration Date' 
    * @return
    */
   public Date getValidTo() throws NoSuchFieldException {
      return ((DateField)getSubfield(CVCTagEnum.EXPIRATION_DATE)).getDate();
   }
   
   /**
    * Returns 'Certificate Authority Reference'
    * Since this field is optional in a CVCRequest this method may return null
    * @return
    */
   public CAReferenceField getAuthorityReference() throws NoSuchFieldException {
      return (CAReferenceField)getOptionalSubfield(CVCTagEnum.CA_REFERENCE);
   }

   /**
    * Returns the public key
    * @return
    */
   public CVCPublicKey getPublicKey() throws NoSuchFieldException {
      return (CVCPublicKey)getSubfield(CVCTagEnum.PUBLIC_KEY);
   }

   /**
    * Returns 'Certificate Holder Reference'
    * @return
    */
   public HolderReferenceField getHolderReference() throws NoSuchFieldException {
      return (HolderReferenceField)getSubfield(CVCTagEnum.HOLDER_REFERENCE);
   }

   /**
    * Returns 'Certificate Extensions'
    * @return
    */
   public CVCertificateExtensions getCertificateExtensions() throws NoSuchFieldException {
      return (CVCertificateExtensions)getSubfield(CVCTagEnum.CERTIFICATE_EXTENSIONS);
   }

}
