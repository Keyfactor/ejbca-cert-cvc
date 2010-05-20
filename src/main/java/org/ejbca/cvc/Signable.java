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
 * Interface for signable classes, forcing them to implement
 * a method for getting the data to be signed
 *
 * @version $Id$
 */
public interface Signable {

   /**
    * Returns the data to be signed
    * @return
    * @throws ConstructionException
    */
   public byte[] getTBS() throws ConstructionException;

}
