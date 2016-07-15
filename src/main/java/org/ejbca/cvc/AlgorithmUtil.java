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

import java.util.HashMap;

/**
 * Utility for mapping a String of type "SHA1WITHRSA" to our own type OIDFIeld.
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class AlgorithmUtil {

   private static HashMap<String, OIDField> algorithmMap = new HashMap<String, OIDField>();
   private static HashMap<String, String> conversionMap = new HashMap<String, String>();
   
   static {
      algorithmMap.put("SHA1WITHRSA",          CVCObjectIdentifiers.id_TA_RSA_v1_5_SHA_1);
      algorithmMap.put("SHA256WITHRSA",        CVCObjectIdentifiers.id_TA_RSA_v1_5_SHA_256);
      algorithmMap.put("SHA512WITHRSA",        CVCObjectIdentifiers.id_TA_RSA_v1_5_SHA_512);
      algorithmMap.put("SHA1WITHRSAANDMGF1",   CVCObjectIdentifiers.id_TA_RSA_PSS_SHA_1);
      algorithmMap.put("SHA256WITHRSAANDMGF1", CVCObjectIdentifiers.id_TA_RSA_PSS_SHA_256);
      algorithmMap.put("SHA512WITHRSAANDMGF1", CVCObjectIdentifiers.id_TA_RSA_PSS_SHA_512);
      // Because CVC certificates does not use standard X9.62 signature encoding we have CVC variants of the ECDSA signature algorithms
      // skip SHA1WITHCVC-ECDSA etc since we have to convert the signature manually to support HSM providers
      algorithmMap.put("SHA1WITHECDSA",        CVCObjectIdentifiers.id_TA_ECDSA_SHA_1);
      algorithmMap.put("SHA224WITHECDSA",      CVCObjectIdentifiers.id_TA_ECDSA_SHA_224);
      algorithmMap.put("SHA256WITHECDSA",      CVCObjectIdentifiers.id_TA_ECDSA_SHA_256);
      algorithmMap.put("SHA384WITHECDSA",      CVCObjectIdentifiers.id_TA_ECDSA_SHA_384);
      algorithmMap.put("SHA512WITHECDSA",      CVCObjectIdentifiers.id_TA_ECDSA_SHA_512);

   }

   static {
	   // Because CVC certificates does not use standard X9.62 signature encoding we have CVC variants of the ECDSA signature algorithms
	   // We have these to make it easier for folks by letting them use the regular style algorithm names
      // skip SHA1WITHCVC-ECDSA etc since we have to convert the signature manually to support HSM providers
	   conversionMap.put("SHA1WITHECDSA",        "SHA1WITHECDSA");
	   conversionMap.put("SHA224WITHECDSA",      "SHA224WITHECDSA");
	   conversionMap.put("SHA256WITHECDSA",      "SHA256WITHECDSA");
	   conversionMap.put("SHA384WITHECDSA",      "SHA384WITHECDSA");
	   conversionMap.put("SHA512WITHECDSA",      "SHA512WITHECDSA");

   }

   /**
    * Returns the OIDField associated with 'algorithmName'
    * @param algorithmName
    * @return
    */
   public static OIDField getOIDField(String algorithmName) {
      OIDField oid = algorithmMap.get(convertAlgorithmNameToCVC(algorithmName));
      if( oid==null ) {
         throw new IllegalArgumentException("Unsupported algorithmName: " + algorithmName);
      }
      return oid;
   }

   /**
    * Some (ECDSA) algorithms requires use of particular CVC-ECDSA algorithm names, so 
    * we sue this conversion map to translate from regular (SHA1WithECDSA) names to CVC (SHA1WithCVC-ECDSA) names. 
    */
   public static String convertAlgorithmNameToCVC(String algorithmName) {
	   String name = conversionMap.get(algorithmName.toUpperCase());
	   if (name != null) {
		   return name;
	   }
	   return algorithmName.toUpperCase();
   }
   
   /**
    * Returns algorithmName for a given OID
    * @param oid
    * @return
    */
   public static String getAlgorithmName(OIDField oid){
      for( String key : algorithmMap.keySet() ){
         OIDField oidfield = algorithmMap.get(key);
         if( oidfield.getValue().equals(oid.getValue()) ){
            return key;
         }
      }
      throw new IllegalArgumentException("Unknown OIDField: " + oid.getValue());
   }

}
