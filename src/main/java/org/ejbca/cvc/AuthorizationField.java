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
 * Klassen representerar f�lt f�r 'Roles and access rights' i CVC.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class AuthorizationField
      extends AbstractDataField {

   private AuthorizationRoleEnum role;
   private AccessRightEnum rights;
   
   
   AuthorizationField(){
      super(CVCTagEnum.ROLE_AND_ACCESS_RIGHTS);
   }

   /**
    * Konstruktor som tar de enskilda f�lten som argument
    * @param role
    * @param rights
    */
   AuthorizationField(AuthorizationRoleEnum role, AccessRightEnum rights){
      this();
      this.role = role;
      this.rights = rights;
   }

   /**
    * Konstruktor f�r att avkoda byte-data
    * @param data
    */
   AuthorizationField(byte[] data){
      this();
      if( data.length!=1 ){
         throw new IllegalArgumentException("byte array length must be 1");
      }
      this.role = getRoleFromByte(data[0]);
      this.rights = getRightsFromByte(data[0]);
   }

   /**
    * Returnerar roll
    * @return
    */
   public AuthorizationRoleEnum getRole() {
      return this.role;
   }

   /**
    * Returnerar beh�righet till datagrupper
    * @return
    */
   public AccessRightEnum getAccessRight() {
      return this.rights;
   }

   @Override
   protected byte[] getEncoded() {
      return new byte[]{ (byte)(role.getValue() | rights.getValue()) };
   }

   @Override
   protected String valueAsText() {
      String txt = StringConverter.byteToHex(getEncoded()) + ": ";
      switch( role ){
         case CVCA : txt += "CVCA";  break;
         case DV_D : txt += "DV-domestic"; break;
         case DV_F : txt += "DV-foreign"; break;
         case IS   : txt += "IS"; break;
         default : txt += " ? ";
      }
      txt += "/";
      
      switch( rights ){
         case READ_ACCESS_DG3_AND_DG4 : txt += "DG3+DG4"; break;
         case READ_ACCESS_DG4  : txt += "DG4";  break;
         case READ_ACCESS_DG3  : txt += "DG3";  break;
         case READ_ACCESS_NONE : txt += "none"; break;
         default : txt = " ? ";
      }
      
      return txt;
   }

   
   /* �vers�tter bytev�rde till AuthorizationRole */
   private AuthorizationRoleEnum getRoleFromByte(byte b){
      byte testVal = (byte)(b & 0xC0);
      AuthorizationRoleEnum foundRole = null;
      for( AuthorizationRoleEnum aRole : AuthorizationRoleEnum.values() ){
         if( testVal == aRole.getValue() ) {
            foundRole = aRole;
            break;
         }
      }
      return foundRole;
   }

   /* �vers�tter bytev�rde till AccessRight */
   private AccessRightEnum getRightsFromByte(byte b){
      byte testVal = (byte)(b & 0x03);
      AccessRightEnum foundRight = null;
      for( AccessRightEnum right : AccessRightEnum.values() ){
         if( testVal == right.getValue() ) {
            foundRight = right;
            break;
         }
      }
      return foundRight;
   }

}
