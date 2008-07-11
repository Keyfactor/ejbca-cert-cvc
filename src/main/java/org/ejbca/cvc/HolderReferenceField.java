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


/**
 * Representerar f�ltet Holder Reference.
 * Egentligen lagras bara en str�ng men p� detta s�tt f�s en bra 
 * validering av indata.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class HolderReferenceField
      extends ReferenceField {

   /**
    * Konstruktor som validerar de enskilda f�lten.
    * 
    * @param country - CountryCode enligt ISO 3166-1 ALPHA-2 (2 tecken)
    * @param mnemonic - Holder Mnemonic (upp till 9 tecken)
    * @param seq - Sequence Number (exakt 5 alfanumeriska tecken)
    */
   public HolderReferenceField(String country, String mnemonic, String seq) {
      super(CVCTagEnum.HOLDER_REFERENCE, country, mnemonic, seq);
   }

   
   /**
    * Konstruktor f�r att avkoda byte-data
    * @param data
    */
   public HolderReferenceField(byte[] data) {
      super(CVCTagEnum.HOLDER_REFERENCE, data);
   }

}
