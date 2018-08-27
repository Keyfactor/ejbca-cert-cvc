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
public class CVCAuthorizationTemplate
      extends AbstractSequence {

   private static CVCTagEnum[] allowedFields = new CVCTagEnum[] {
      CVCTagEnum.OID, 
      CVCTagEnum.ROLE_AND_ACCESS_RIGHTS
   };

   @Override
   CVCTagEnum[] getAllowedFields() {
      return allowedFields;
   }

   /**
    * Default constructor
    */
   CVCAuthorizationTemplate(){
      super(CVCTagEnum.HOLDER_AUTH_TEMPLATE);
   }
   
   /**
    * Constructor taking the individual fields
    * @param role
    * @param rights
    */
   public CVCAuthorizationTemplate(AuthorizationRoleEnum role, AccessRightEnum rights) throws ConstructionException {
      this();
      
      addSubfield(CVCObjectIdentifiers.id_EAC_ePassport);
      addSubfield(new AuthorizationField(role, rights));
   }


   /**
    * Returns the Object Identifier as a String
    * @return
    */
   public String getObjectIdentifier() throws NoSuchFieldException {
      return ((OIDField)getSubfield(CVCTagEnum.OID)).getValue();
   }

   /**
    * Returns AuthorizationField
    * @return
    */
   public AuthorizationField getAuthorizationField() throws NoSuchFieldException {
      return (AuthorizationField)getSubfield(CVCTagEnum.ROLE_AND_ACCESS_RIGHTS);
   }

}
