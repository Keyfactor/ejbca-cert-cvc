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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.ejbca.cvc.exception.ConstructionException;


/**
 * Represents a CVC sequence, i e contains one or more subfields
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public abstract class AbstractSequence extends CVCObject {

   private static final long serialVersionUID = 1L;
	
   private final Map<CVCTagEnum, CVCObject> subfields = new HashMap<CVCTagEnum, CVCObject>();
   private final List<CVCTagEnum> allowedFields;

   /**
    * Constructor, must supply the tag
    * @param type
    */
   AbstractSequence(final CVCTagEnum type){
      super(type);
      this.allowedFields = Arrays.asList(getAllowedFields());
   }

   /**
    * Adds a subfield to this sequence. Nothing happens if the argument is null.
    * @param field
    * @throws ConstructionException if the supplied field is not allowed in this sequence, or the field already exists.
    */
   void addSubfield(final CVCObject field) throws ConstructionException {
	   addSubfield(field, false);
   }
   /**
    * Adds a subfield to this sequence, as above, but with the possibility to overwrite an existing
    * field with a new one.
    * @param field the field to add
    * @param override true if an existing field should be overwritten, false if an exception should be thrown if the field already exists
    * @throws ConstructionException if the supplied field is not allowed in this sequence, or already exists and override == false.
    */
   void addSubfield(final CVCObject field, boolean override) throws ConstructionException {
      if( field!=null ){
         if( allowedFields.contains(field.getTag() )) {
            if( subfields.containsKey(field.getTag()) && !override){
               throw new ConstructionException("Field " + field.getTag() + " has already been added to " + getClass().getName());
            }
            else {
               field.setParent(this);
               subfields.put(field.getTag(), field);
            }
         }
         else {
            throw new ConstructionException("Field " + field.getTag() + " not allowed in " + getClass().getName());
         }
      }
   }


   /**
    * Returns tags for all allowed subfields, in the same order as they
    * appear when DER-encoded
    * @return
    */
   protected abstract CVCTagEnum[] getAllowedFields();
   

   /**
    * Returns a mandatory subfield
    * @param fieldTag
    * @return
    * @throws NoSuchFieldException if the subfield hasn't been added
    */
   CVCObject getSubfield(final CVCTagEnum fieldTag) throws NoSuchFieldException {
      final CVCObject subfield = subfields.get(fieldTag);
      if( subfield==null ){
          throw new NoSuchFieldException("Could not find subfield " + fieldTag);
      } else {
          return subfield;
      }
   }


   /**
    * Returns optional subfield (no Exception is thrown).
    * @param tag
    * @return AbstractDataField or null if the field hasn't been added
    */
   CVCObject getOptionalSubfield(final CVCTagEnum tag) {
      return subfields.get(tag);
   }

   /**
    * Returns all added subfields
    * @return
    */
   protected Collection<CVCObject> getSubfields() {
      return subfields.values();
   }

   @Override
   public int encode(DataOutputStream pOut) throws IOException {
      // Iterate over the subfields, sum up the lengths and write it the header
      
      // Get a local DataOutputStream to write the subfields to,
      // so we know have many bytes we have written
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      DataOutputStream dout = new DataOutputStream(bout);
      int seqLength = 0;
      for( CVCObject subfield : getEncodableFields() ){
         seqLength += subfield.encode(dout);
      }
      dout.close();

      int tag = getTag().getValue();
      int s0 = pOut.size();
      pOut.write( toByteArray(tag) );
      pOut.write( encodeLength(seqLength) );
      pOut.write( bout.toByteArray() );

      return pOut.size()-s0;
   }

   
   /**
    * Returns all subfields for DER-encoding
    * @return
    */
   protected List<CVCObject> getEncodableFields() {
      return getOrderedSubfields();
   }

   /**
    * Helper for creating a DER-encoded byte array.
    * @return
    * @throws IOException
    */
   public byte[] getDEREncoded() throws IOException {
      
      ByteArrayOutputStream bout = null;
      try {
         bout = new ByteArrayOutputStream();
         DataOutputStream dout = new DataOutputStream(bout);

         // Encode!
         encode(dout);

      }
      finally {
         if( bout!=null )
            bout.close();
      }
      return bout.toByteArray();
   }

   /**
    * Returns this object as text, including tag value
    * @param tab
    * @return
    */
   @Override
   public String getAsText(String tab) {
      return getAsText(tab, true);
   }

   /**
    * {@inheritDoc}
    */
   @Override
   public String getAsText(String tab, boolean showTagNo) {
      StringBuffer sb = new StringBuffer();
      sb.append(super.getAsText(tab, showTagNo));
      for( CVCObject field : getOrderedSubfields() ){
         sb.append(NEWLINE);
         sb.append(field.getAsText(tab + "   ", showTagNo));
      }
      return sb.toString();
   }

   
   /**
    * Returns a List of ordered subfields
    */
   protected List<CVCObject> getOrderedSubfields() {
      List<CVCObject> orderedList = new ArrayList<CVCObject>();
      for( CVCTagEnum tag : allowedFields ){
         CVCObject subfield = subfields.get(tag);
         // Bara f�r att ett f�lt �r till�tet kanske det inte m�ste finnas
         if( subfield!=null ){
            orderedList.add(subfield);
         }
      }
      return orderedList;
   }

}
