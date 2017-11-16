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
 * A "Certificate Extensions" sequence in a CV certificate. It contains CVCDiscretionaryDataTemplate objects.
 * 
 * @author Samuel Lidén Borell, PrimeKey Solutions AB
 * @version $Id$
 * 
 */
public class CVCertificateExtensions extends AbstractArray {

   private static final long serialVersionUID = 1L;

   @Override
   protected CVCTagEnum getAllowedField() {
      return CVCTagEnum.DISCRETIONARY_DATA_TEMPLATE;
   }

   /**
    * Default constructor
    */
   CVCertificateExtensions(){
      super(CVCTagEnum.CERTIFICATE_EXTENSIONS);
   }

   /**
    * Constructor taking a list of certificate extensions (wrapped in Discretionary Data Template objects).
    * @param extensions Extensions with OIDs and extension specific data
    */
   public CVCertificateExtensions(final Collection<CVCDiscretionaryDataTemplate> extensions) throws ConstructionException {
      this();
      for (CVCDiscretionaryDataTemplate ext : extensions) {
          addSubfield(ext);
      }
   }

   /**
    * Returns the certificate extensions (wrapped in Discretionary Data Template objects).
    * Each Discretionary Data Template object contains an OID and the raw extension specific data.
    */
   public List<CVCDiscretionaryDataTemplate> getExtensions() {
      List<CVCDiscretionaryDataTemplate> exts = new ArrayList<CVCDiscretionaryDataTemplate>();
      for (CVCObject ext : getEncodableFields()) {
          exts.add((CVCDiscretionaryDataTemplate) ext);
      }
      return exts;
   }

}
