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

import java.io.IOException;

/**
 * Klassen representerar det data som ska signeras ('To Be Signed')
 * dvs DER-kodad version av en viss typ av AbstractSequence inklusive tagg och l�ngd.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TBSData {

   private byte[] data;

   /**
    * Ska inte instansieras 'tom'
    * @param data
    */
   private TBSData(byte[] data){
      this.data = data;
   }

   /**
    * Skapar instans av klassen fr�n en CVCertificate
    * @param body
    * @return
    * @throws IOException
    */
   static TBSData getInstance(CVCertificate cert) throws IOException {
      return getTBS(cert);
   }

   /**
    * Skapar instans av klassen fr�n en CVCertificateBody
    * @param body
    * @return
    * @throws IOException
    */
   static TBSData getInstance(CVCertificateBody body) throws IOException {
      return getTBS(body);
   }


   // Hj�lpmetod
   private static TBSData getTBS(AbstractSequence seq) throws IOException {
      return new TBSData(seq.getDEREncoded());
   }

   /**
    * Returnerar datat som ska signeras
    * @return
    */
   public byte[] getEncoded() {
      return data;
   }

}
