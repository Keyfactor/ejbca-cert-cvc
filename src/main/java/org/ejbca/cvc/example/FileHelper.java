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
package org.ejbca.cvc.example;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;


/**
 * Utility for reading and writing files.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public final class FileHelper {

	private FileHelper() {}
	
   /**
    * Loads a file
    * @param path
    * @return
    * @throws IOException
    */
   public static byte[] loadFile(final String path) throws IOException {
      return loadFile(new File(path));
   }

   /**
    * Loads a file
    * @param file
    * @return
    * @throws IOException
    */
   public static byte[] loadFile(final File file) throws IOException {
      byte[] dataBuffer = null;
      FileInputStream inStream = null;
      try {
         // Simple file loader...
         final int length = (int)file.length();
         dataBuffer = new byte[length];
         inStream = new FileInputStream(file);

         int offset = 0;
         int readBytes = 0;
         boolean readMore = true;
         while (readMore) {
            readBytes = inStream.read(dataBuffer, offset, length - offset);
            offset += readBytes;
            readMore = readBytes > 0 && offset != length;
         }
      }
      finally {
         try {
            if (inStream != null) {
               inStream.close();
            }
         } catch (IOException e1) {
            System.out.println("loadFile - error when closing: " + e1); 
         }
      }
      return dataBuffer;
   }

   /**
    * Writes data to a file
    * @param file
    * @param data
    * @throws IOException
    */
   public static void writeFile(final File file, final byte[] data) throws IOException {
      FileOutputStream outStream = null;
      BufferedOutputStream bout = null;
      try {
         outStream = new FileOutputStream(file);
         bout = new BufferedOutputStream(outStream, 1000);
         bout.write(data);
      }
      finally {
         if( bout!=null ) {
            bout.close();
         }
      }
   }

}
