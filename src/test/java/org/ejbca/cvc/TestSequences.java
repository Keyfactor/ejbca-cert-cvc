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

import java.security.Security;
import java.util.Arrays;
import java.util.Date;

import junit.framework.TestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.AbstractDataField;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.ByteField;
import org.ejbca.cvc.CVCAuthorizationTemplate;
import org.ejbca.cvc.CVCTagEnum;
import org.ejbca.cvc.DateField;
import org.ejbca.cvc.GenericPublicKeyField;
import org.ejbca.cvc.exception.ConstructionException;


/**
 * Denna klass testar grundl�ggande funtionalitet i Sequences,
 * dvs arvtagare till AbstractSequence
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TestSequences
      extends TestCase implements CVCTest {

   /** DER-kodning av en AuthorizationTemplate f�r IS, DG3 */
   static byte[] AuthorizationTemplateDER = 
      new byte[] { /* tag */    0x7F, 0x4C, 
                    /* length */ 0x0E, 
                           /* oid tag */ 0x06, 
                           /* length  */ 0x09,  /* Nedan kodas v�rdet f�r id_EAC_ePassport */
                           /* data    */ 0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x01, 0x02, 0x01, 
                           /* role+access tag */ 0x53, 
                           /* length */ 0x01, 
                           /* data   */ 0x01 };

   protected void setUp() throws Exception {
      // Installera BC som provider 
      Security.addProvider(new BouncyCastleProvider());
   }

   protected void tearDown() throws Exception {
      // Installera BC som provider 
      Security.removeProvider("BC");
   }

   
   /** Kontroll: Kan bara l�gga till vissa subf�lt till en sequence  */
   public void testAddUnexpectedSubfield() throws Exception {
      GenericPublicKeyField generic = new GenericPublicKeyField();
      // Detta ska inte g�, EFFECTIVE_DATE �r inte en allowedField f�r GenericPublicKeyField
      try {
         AbstractDataField subfield = new DateField(CVCTagEnum.EFFECTIVE_DATE, new Date());
         generic.addSubfield(subfield);
         throw new Exception("Field is not allowed in GenericPublicKeyField: " + subfield.getTag());
      }
      catch( ConstructionException e ){
         // Vi f�rv�ntas hamna h�r
      }
   }

   /** Kontroll: Kan bara l�gga till visst subf�lt en g�ng */
   public void testAddSubfieldTwice() throws Exception {
      GenericPublicKeyField generic = new GenericPublicKeyField();

      AbstractDataField subfield = new ByteField(CVCTagEnum.MODULUS, new byte[]{1,2,3,4,5,6,7,8,9});
      generic.addSubfield(subfield);
      try {
         // Detta ska inte g�, MODULUS �r redan tillagd
         generic.addSubfield(subfield);
         throw new Exception("Cannot add same field typ again: " + subfield.getTag());
      }
      catch( ConstructionException e ){
         // Vi f�rv�ntas hamna h�r
      }
   }

   /** Kontroll: Genererad byte-array ska ha visst inneh�ll */
   public void testDEREncode() throws Exception {
      // Testa med en liten sequence f�r enkelhets skull
      CVCAuthorizationTemplate authTemplate = new CVCAuthorizationTemplate(AuthorizationRoleEnum.IS, AccessRightEnum.READ_ACCESS_DG3);
      byte[] der = authTemplate.getDEREncoded();
      
      // J�mf�r byte f�r byte...
      assertTrue("Arrays not equal", Arrays.equals(der, AuthorizationTemplateDER));
   }

}
