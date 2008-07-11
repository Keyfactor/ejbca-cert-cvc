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

import org.ejbca.cvc.exception.ConstructionException;


/**
 * Klassen representerar ett CVC-f�lt som �r en sequence,
 * dvs best�r av en samling subf�lt.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public abstract class AbstractSequence extends CVCObject {

   private HashMap<CVCTagEnum, CVCObject> subfields = new HashMap<CVCTagEnum, CVCObject>();
   private List<CVCTagEnum> allowedFields;

   /**
    * Enda konstruktorn, kr�ver identifierare i form av tagg
    * @param type
    */
   AbstractSequence(CVCTagEnum type){
      super(type);
      this.allowedFields = Arrays.asList(getAllowedFields());
   }

   /**
    * L�gger till ett subf�lt. Om argumentet �r null h�nder ingenting.
    * @param field
    * @throws IllegalArgumentException om subf�lten inte �r till�tet i denna sequence
    */
   void addSubfield(CVCObject field) throws ConstructionException {
      if( field!=null ){
         if( allowedFields.contains(field.getTag() )) {
            if( subfields.containsKey(field.getTag()) ){
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
    * Returnerar array med alla till�tna taggar i denna sequence,
    * sorterade i den ordning de ska komma vid DER-kodning
    * @return
    */
   abstract CVCTagEnum[] getAllowedFields();
   

   /**
    * H�mtar visst subf�lt
    * @param fieldTag
    * @return
    * @throws NoSuchFieldException om angivet f�lt inte kunde hittas
    */
   CVCObject getSubfield(CVCTagEnum fieldTag) throws NoSuchFieldException {
      CVCObject subfield = subfields.get(fieldTag);
      if( subfield!=null ){
         return subfield;
      }
      else {
         throw new NoSuchFieldException("Could not find subfield " + fieldTag);
      }
   }


   /**
    * H�mtar visst subf�lt som inte �r obligatoriskt (inget Exception kastas).
    * @param tag
    * @return AbstractDataField eller null om f�ltet inte hittas
    */
   CVCObject getOptionalSubfield(CVCTagEnum tag) {
      return subfields.get(tag);
   }

   /**
    * Returnerar alla tillagda subf�lt
    * @return
    */
   Collection<CVCObject> getSubfields() {
      return subfields.values();
   }

   @Override
   public int encode(DataOutputStream pOut) throws IOException {
      // Iterera �ver subf�lten och summera l�ngderna, skriv sedan detta i headern
      
      // Skaffa en lokal DataOutputStream att skriva subf�lten i,
      // detta f�r att h�lla koll p� sammanlagd l�ngd.
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
    * �Verlagringsbar metod som returnerar de f�lt som ska
    * DER-kodas. Returnerar som default alla f�lt som �r icke-null,
    * i den ordning som getAllowedFields() returnerat.
    * @return
    */
   protected List<CVCObject> getEncodableFields() {
      return getOrderedSubfields();
   }

   /**
    * Hj�lpmetod f�r att skapa en DER-kodad bytearray.
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
    * Returnerar objektet som en str�ngbeskrivning,
    * inklusive tagg-v�rden
    * @param tab
    * @return
    */
   public String getAsText(String tab) {
      return getAsText(tab, true);
   }

   /**
    * {@inheritDoc}
    */
   public String getAsText(String tab, boolean showTagNo) {
      StringBuffer sb = new StringBuffer();
      sb.append(super.getAsText(tab, showTagNo));
      for( CVCObject field : getOrderedSubfields() ){
         sb.append(NEWLINE);
         sb.append(field.getAsText(tab + "   ", showTagNo));
      }
      return sb.toString();
   }

   
   // Returnerar en lista med subf�lt sorterade i best�md ordning
   private List<CVCObject> getOrderedSubfields() {
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
