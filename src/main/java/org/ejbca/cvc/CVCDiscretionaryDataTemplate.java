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
 * Represents the field 'Discretionary Data Template', which is used to wrap certificate extensions.
 * Described in the BSI TR-03110 Part 3 v2.2, page 89.
 * 
 * @author Samuel Lidén Borell, PrimeKey Solutions AB
 * @version $Id$
 * 
 */
public class CVCDiscretionaryDataTemplate extends AbstractSequence {

   private static final long serialVersionUID = 1L;

   private static CVCTagEnum[] allowedFields = new CVCTagEnum[] {
      CVCTagEnum.OID,
      CVCTagEnum.ARBITRARY_DATA
   };

   @Override
   protected CVCTagEnum[] getAllowedFields() {
      return allowedFields;
   }

   /**
    * Default constructor
    */
   CVCDiscretionaryDataTemplate(){
      super(CVCTagEnum.DISCRETIONARY_DATA_TEMPLATE);
   }
   
   /**
    * Constructor taking the individual fields. This constructor can be used internally only.
    * @param oid Object Identifier representing the extension. There's also an overloaded constructor that takes a string for the OID.
    * @param data Data for the extension.
    */
   CVCDiscretionaryDataTemplate(final OIDField oid, final ByteField data) throws ConstructionException {
      this();
      
      addSubfield(oid);
      addSubfield(data);
   }
   
   /**
    * Constructor taking the individual fields. This constructor can be used with custom OIDs.
    * @param oid Object Identifier representing the extension, as a string.
    * @param data Data for the extension.
    */
   public CVCDiscretionaryDataTemplate(final String oid, final byte[] data) throws ConstructionException {
      this(new OIDField(oid), new ByteField(CVCTagEnum.ARBITRARY_DATA, data));
   }

   /**
    * Returns the Object Identifier as a String
    */
   public String getObjectIdentifier() throws NoSuchFieldException {
      return ((OIDField)getSubfield(CVCTagEnum.OID)).getValue();
   }

   /**
    * Returns the extension data.
    */
   public byte[] getExtensionData() throws NoSuchFieldException {
      final ByteField bf = (ByteField) getSubfield(CVCTagEnum.ARBITRARY_DATA);
      return bf.getData();
   }

}
