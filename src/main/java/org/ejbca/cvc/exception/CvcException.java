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
 * Base class for CVC-specific exceptions
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class CvcException extends Exception {

	private static final long serialVersionUID = 1L;

   /**
    * @see Exception
    */
   public CvcException() {
      super();
   }

   /**
    * @see Exception
    */
   public CvcException(final String msg) {
      super(msg);
   }

   /**
    * @see Exception
    */
   public CvcException(final Throwable t){
      super(t);
   }

   /**
    * @see Exception
    */
   public CvcException(final String msg, final Throwable t){
      super(msg, t);
   }
}
