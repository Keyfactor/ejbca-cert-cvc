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

import org.ejbca.cvc.util.StringConverter;

/**
 * Represents field 'Roles and access rights' i CVC.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class AuthorizationField
      extends AbstractDataField {

   private static final long serialVersionUID = -5478250843535697147L;
   
   private AuthorizationRole role;
   private AccessRights rights;
   
   
   AuthorizationField(){
      super(CVCTagEnum.ROLE_AND_ACCESS_RIGHTS);
   }

   /**
    * Constructor taking an AuthorizationRole and an AccessRight.
    * The parameters should be of matching types (e.g. AuthorizationRoleAuthTermEnum and AccessRightAuthTerm) 
    * @param role
    * @param rights
    */
   AuthorizationField(AuthorizationRole role, AccessRights rights){
      this();
      this.role = role;
      this.rights = rights; 
   }
   
   AuthorizationField(AuthorizationRoleEnum role, AccessRightEnum rights) {
      this((AuthorizationRole)role, (AccessRights)rights);
   }

   /**
    * Constructor for decoding DER-encoded data.
    * The fixEnumTypes method must be called as soon as the OID is known
    * (CVCObjectIdentifiers.id_EAC_ePassport, etc.)
    * @param data
    */
   AuthorizationField(byte[] data){
      this();
      if( data.length<1 ){
         throw new IllegalArgumentException("byte array length must be at least 1");
      }
      this.role = new AuthorizationRoleRawValue(data[0]);
      this.rights = new AccessRightsRawValue(data);
   }

   /**
    * Returns role
    * @throws UnsupportedOperationException if the rights is of authentication or signing terminal type.
    * 
    * @deprecated Use {@link #getAuthRole()} instead
    * 
    */
   @Deprecated
   public AuthorizationRoleEnum getRole() {
      if (!(role instanceof AuthorizationRoleEnum)) {
         throw new UnsupportedOperationException("Attempted to use deprecated getRole method with in an AT or ST certificate chain. It handles IS only.");
      }
      return (AuthorizationRoleEnum)this.role;
   }
   
   /**
    * Returns the role. The return value is one of the AuthorizationRole* types.
    * @see AuthorizationRoleEnum
    * @see AuthorizationRoleAuthTermEnum
    * @see AuthorizationRoleSignTermEnum
    */
   public AuthorizationRole getAuthRole() {
      return this.role;
   }

   /**
    * Returns access rights
    * @throws UnsupportedOperationException if the rights is of authentication or signing terminal type.
    * 
    * @deprecated Use {@link #getAccessRights()} instead
    */
   @Deprecated
   public AccessRightEnum getAccessRight() {
      if (!(rights instanceof AccessRightEnum)) {
         throw new UnsupportedOperationException("Attempted to use deprecated getAccessRight method with an AT or ST certificate chain. It handles IS only.");
      }
      return (AccessRightEnum)this.rights;
   }
   
   /**
    * Returns access rights. The return value is one of the AccessRight* types.
    * @see AccessRightEnum
    * @see AccessRightAuthTerm
    * @see AccessRightSignTermEnum
    */
   public AccessRights getAccessRights() {
      return this.rights;
   }

   @Override
   protected byte[] getEncoded() {
      byte[] encoded = rights.getEncoded();
      encoded[0] |= role.getValue();
      return encoded;
   }

   @Override
   protected String valueAsText() {
      return StringConverter.byteToHex(getEncoded()) + ": " + role + "/" + rights;
   }

   
   /** Translates a byte to AuthorizationRole */
   private static AuthorizationRole getRoleFromByte(OIDField oid, byte b){
      byte testVal = (byte)(b & 0xC0);
      
      AuthorizationRole values[];
      if (CVCObjectIdentifiers.id_EAC_ePassport.equals(oid)) {
         values = AuthorizationRoleEnum.values();
      } else if (CVCObjectIdentifiers.id_EAC_roles_ST.equals(oid)) {
         values = AuthorizationRoleSignTermEnum.values();
      } else if (CVCObjectIdentifiers.id_EAC_roles_AT.equals(oid)) {
         values = AuthorizationRoleAuthTermEnum.values();
      } else {
         throw new IllegalArgumentException("incorrect or unsupported OID");
      }
      
      AuthorizationRole foundRole = null;
      for( AuthorizationRole aRole : values ){
         if( testVal == aRole.getValue() ) {
            foundRole = aRole;
            break;
         }
      }
      return foundRole;
   }

   /** Translates a byte array to AccessRights */
   private static AccessRights getRightsFromBytes(OIDField oid, byte[] data){
      if (CVCObjectIdentifiers.id_EAC_ePassport.equals(oid)) {
         if (data.length!=1) {
            throw new IllegalArgumentException("byte array length must be 1, was "+data.length);
         }
         byte testVal = (byte)(data[0] & 0x03);
         AccessRightEnum foundRight = null;
         for( AccessRightEnum right : AccessRightEnum.values() ){
            if( testVal == right.getValue() ) {
               foundRight = right;
               break;
            }
         }
         return foundRight;
      } else if (CVCObjectIdentifiers.id_EAC_roles_ST.equals(oid)) {
         if (data.length!=1) {
            throw new IllegalArgumentException("byte array length must be 1, was "+data.length);
         }
         byte testVal = (byte)(data[0] & 0x03);
         AccessRightSignTermEnum foundRight = null;
         for( AccessRightSignTermEnum right : AccessRightSignTermEnum.values() ){
            if( testVal == right.getValue() ) {
               foundRight = right;
               break;
            }
         }
         return foundRight;
      } if (CVCObjectIdentifiers.id_EAC_roles_AT.equals(oid)) {
         if (data.length!=5) {
            throw new IllegalArgumentException("byte array length must be 5, was "+data.length);
         }
         return new AccessRightAuthTerm(data);
      } else {
         throw new IllegalArgumentException("incorrect or unsupported OID");
      }
   }

   /**
    * Re-creates the role/rights objects as the correct classes.
    * This is necessary when deserializing from binary data.
    */
   void fixEnumTypes(OIDField oid) {
      role = getRoleFromByte(oid, role.getValue());
      rights = getRightsFromBytes(oid, rights.getEncoded());
   }

}
