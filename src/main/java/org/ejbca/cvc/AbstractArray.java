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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.ejbca.cvc.exception.ConstructionException;


/**
 * Represents a CVC sequence, i e contains one or more subfields.
 * This variant allows multiple objects of the same type. It preserves order of the objects.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public abstract class AbstractArray extends AbstractSequence {

   private static final long serialVersionUID = 1L;

   private final List<CVCObject> subfields = new ArrayList<CVCObject>();
   private final CVCTagEnum allowedField;

   /**
    * Constructor, must supply the tag
    * @param type
    */
   AbstractArray(final CVCTagEnum type){
      super(type);
      this.allowedField = getAllowedField();
   }

   /**
    * Adds a subfield to this sequence. Nothing happens if the argument is null.
    * @param field
    * @throws ConstructionException if the supplied field is not allowed in this sequence.
    */
   @Override
   void addSubfield(final CVCObject field) throws ConstructionException {
      if (field != null) {
         if (allowedField != field.getTag()) {
            throw new ConstructionException("Field " + field.getTag() + " not allowed in " + getClass().getName());
         }
         field.setParent(this);
         subfields.add(field);
      }
   }


   /**
    * Returns the allow tag for the subfields.
    * @return
    */
   protected abstract CVCTagEnum getAllowedField();
   
   @Override
   protected final CVCTagEnum[] getAllowedFields() {
       return new CVCTagEnum[] { getAllowedField() };
   }
   

   @Override
   protected final CVCObject getSubfield(final CVCTagEnum fieldTag) throws NoSuchFieldException {
      throw new IllegalStateException("Not applicable to AbstractArray");
   }

   @Override
   protected final CVCObject getOptionalSubfield(final CVCTagEnum tag) {
      throw new IllegalStateException("Not applicable to AbstractArray");
   }

   /**
    * Returns all added subfields
    * @return
    */
   @Override
   protected Collection<CVCObject> getSubfields() {
      return new ArrayList<CVCObject>(subfields);
   }
   
   // Returns a List of ordered subfields
   @Override
   protected List<CVCObject> getOrderedSubfields() {
      return new ArrayList<CVCObject>(subfields);
   }

}
