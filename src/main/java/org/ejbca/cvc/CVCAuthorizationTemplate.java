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

import org.ejbca.cvc.exception.ConstructionException;


/**
 * Represents the field 'Certificate Holder Authorization Template'
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 * 
 */
public class CVCAuthorizationTemplate extends AbstractSequence {

   private static final long serialVersionUID = 1L;
	
   private static CVCTagEnum[] allowedFields = new CVCTagEnum[] {
      CVCTagEnum.OID, 
      CVCTagEnum.ROLE_AND_ACCESS_RIGHTS
   };

   @Override
   protected CVCTagEnum[] getAllowedFields() {
      return allowedFields;
   }

   /**
    * Default constructor
    */
   CVCAuthorizationTemplate(){
      super(CVCTagEnum.HOLDER_AUTH_TEMPLATE);
   }
   
   @Override
   void addSubfield(final CVCObject field) throws ConstructionException {
       super.addSubfield(field);
       // Determine OID and change role/rights enums to the right type
       if (field instanceof AuthorizationField) {
           try {
               AuthorizationField authfield = (AuthorizationField)field;
               OIDField oid = (OIDField)getSubfield(CVCTagEnum.OID);
               authfield.fixEnumTypes(oid);
           } catch (NoSuchFieldException e) {
              throw new ConstructionException("Tried to add an AuthorizationField without an OID", e);
           }
       }
   }
   
   /**
    * Constructor taking the individual fields
    * @param role
    * @param rights
    */
   public CVCAuthorizationTemplate(AuthorizationRole role, AccessRights rights) throws ConstructionException {
      this();
      
      addSubfield(getOIDForEnums(role, rights));
      addSubfield(new AuthorizationField(role, rights));
   }
   
   /**
    * Constructor taking the individual fields. This seemingly redundant overloaded constructor is for
    * binary (.class file) backwards compatibility. It is NOT deprecated to use these argument types.
    */
   public CVCAuthorizationTemplate(AuthorizationRoleEnum role, AccessRightEnum rights) throws ConstructionException {
      this((AuthorizationRole)role, (AccessRights)rights);
   }

   /**
    * Determines the OID to use for the types of the given role/rights objects.
    */
   public static OIDField getOIDForEnums(AuthorizationRole role, AccessRights rights) {
      if (role instanceof AuthorizationRoleEnum && rights instanceof AccessRightEnum) {
         return CVCObjectIdentifiers.id_EAC_ePassport;
      } else if (role instanceof AuthorizationRoleAuthTermEnum && rights instanceof AccessRightAuthTerm) {
         return CVCObjectIdentifiers.id_EAC_roles_AT;
      } else if (role instanceof AuthorizationRoleSignTermEnum && rights instanceof AccessRightSignTermEnum) {
         return CVCObjectIdentifiers.id_EAC_roles_ST;
      } else {
         throw new IllegalArgumentException("Unsupported roles/rights type (or mismatch). Got role of type "+role.getClass().getSimpleName()+", but rights of type "+rights.getClass().getSimpleName());
      }
   }

   /**
    * Returns the Object Identifier as a String
    */
   public String getObjectIdentifier() throws NoSuchFieldException {
      return ((OIDField)getSubfield(CVCTagEnum.OID)).getValue();
   }

   /**
    * Returns AuthorizationField
    */
   public AuthorizationField getAuthorizationField() throws NoSuchFieldException {
      return (AuthorizationField)getSubfield(CVCTagEnum.ROLE_AND_ACCESS_RIGHTS);
   }

}
