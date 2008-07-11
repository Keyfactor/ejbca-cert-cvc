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

import java.util.Arrays;
import java.util.Locale;


/**
 * Representerar f�lten Certificate Authority/Holder Reference.
 * Egentligen lagras bara en str�ng men p� detta s�tt f�r man 
 * b�ttre kontroll av de ing�ende f�lten.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public abstract class ReferenceField
      extends AbstractDataField {

   private String country = null;
   private String mnemonic = null;
   private String sequence = null;

   /**
    * Konstruktor som validerar de enskilda f�lten.
    * 
    * @param country - CountryCode enligt ISO 3166-1 ALPHA-2 (2 tecken)
    * @param mnemonic - Holder Mnemonic (upp till 9 tecken)
    * @param seq - Sequence Number (exakt 5 alfanumeriska tecken)
    */
   public ReferenceField(CVCTagEnum tag, String country, String mnemonic, String seq) {
      super(tag);
      
      if( country.length()!=2 ){
         throw new IllegalArgumentException("Country code length must be 2, was " + country.length());
      }
      if( !isValidCountry(country) ){
         throw new IllegalArgumentException("Unknown country code: " + country);
      }
      if( mnemonic.length()==0 ){
         throw new IllegalArgumentException("Holder mnemonic too short, must have at least one character");
      }
      if( mnemonic.length()>9 ){
         throw new IllegalArgumentException("Holder mnemonic too long, max=9, was " + mnemonic.length());
      }
      if( seq.length()!=5 ){
         throw new IllegalArgumentException("Sequence number must have length 5, was " + seq.length());
      }
      for( int i=0; i<seq.length(); i++ ){
         // validera teckentyperna
         char c = seq.charAt(i);
         if( !Character.isLetterOrDigit(c) ) {
            throw new IllegalArgumentException("Sequence number can only contain alphanumerics: " + seq);
         }
      }
      
      this.country = country;
      this.mnemonic = mnemonic;
      this.sequence = seq;
   }


   /**
    * Konstruktor f�r att avkoda byte-data
    * @param tag
    * @param data
    */
   protected ReferenceField(CVCTagEnum tag, byte[] data) {
      super(tag);
      
      String dataStr = new String(data);
      this.country  = dataStr.substring(0,2);  // Har alltid l�ngd 2
      this.mnemonic = dataStr.substring(2, dataStr.length()-5);
      this.sequence = dataStr.substring(dataStr.length()-5);  // Har alltid l�ngd 5
   }
   
   
   /**
    * Returnerar v�rdet som en konkatenering av country, mnemonic och sequence
    * @return
    */
   public String getConcatenated() {
      return country + mnemonic + sequence;
   }

   /**
    * Returnerar country
    * @return
    */
   public String getCountry() {
      return country;
   }

   /**
    * Returnerar mnemonic
    * @return
    */
   public String getMnemonic() {
      return mnemonic;
   }

   /**
    * Returnerar sequence
    * @return
    */
   public String getSequence() {
      return sequence;
   }


   @Override
   protected byte[] getEncoded() {
      return getConcatenated().getBytes();
   }

   // Validerar landskod enligt ISO 3166
   private boolean isValidCountry(String countryCode) {
      return Arrays.asList(Locale.getISOCountries()).contains(countryCode);
   }
   
   @Override
   public String valueAsText() {
      return country + "/" + mnemonic + "/" + sequence;
   }
   
}
