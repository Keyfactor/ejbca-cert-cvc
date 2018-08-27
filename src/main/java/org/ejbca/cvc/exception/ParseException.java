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
package org.ejbca.cvc.exception;

/**
 * Exception indicating that a byte array could not be parsed as a CVC object
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class ParseException
      extends CvcException {

   /**
    * @see Exception
    */
   public ParseException() {
      super();
   }

   /**
    * @see Exception
    */
   public ParseException(String msg) {
      super(msg);
   }

   /**
    * @see Exception
    */
   public ParseException(Throwable t){
      super(t);
   }

   /**
    * @see Exception
    */
   public ParseException(String msg, Throwable t){
      super(msg, t);
   }

}
