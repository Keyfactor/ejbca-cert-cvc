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
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Date;

import org.ejbca.cvc.exception.ConstructionException;


/**
 * Generates CV-certificates and CVC-requests
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class CertificateGenerator {

   // Only static methods...
   private CertificateGenerator(){
   }

   /**
    * Generates a CVCertificate for testing with the following characteristics:
    * - expires 3 months from today
    * - hash-algorithm is 'SHA1withRSA'
    * - AuthorizationRoleEnum = IS.
    * 
    *   TODO: Move this method to the test cases!
    * 
    * @param keyPair
    * @param caRef
    * @param holderRef
    * @param algorithm SHA1WithRSA, SHA256WithECDSA etc
    * @return
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws NoSuchProviderException
    * @throws InvalidKeyException
    * @throws SignatureException
    */
   public static CVCertificate createTestCertificate(
         PublicKey             publicKey,
         PrivateKey            privateKey,
         CAReferenceField      caRef, 
         HolderReferenceField  holderRef, 
         String algorithm, 
         AuthorizationRoleEnum role) 
   throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, ConstructionException {
      // Skapa default-datum
      Calendar cal1 = Calendar.getInstance();
      Date validFrom = cal1.getTime();
      
      Calendar cal2 = Calendar.getInstance();
      cal2.add(Calendar.MONTH, 3);
      Date validTo = cal2.getTime();
      return createCertificate(
            publicKey, 
            privateKey, 
            algorithm, 
            caRef, 
            holderRef, 
            role,
            AccessRightEnum.READ_ACCESS_DG3_AND_DG4,
            validFrom, 
            validTo, 
            "BC" );
   }


   /**
    * Generates a CVCertificate
    * @param publicKey
    * @param signerKey
    * @param algorithmName
    * @param caRef
    * @param holderRef
    * @param authRole
    * @param validFrom
    * @param validTo
    * @param provider
    * @return
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws NoSuchProviderException
    * @throws InvalidKeyException
    * @throws SignatureException
    * @throws ConstructionException
    */
   public static CVCertificate createCertificate(
         PublicKey              publicKey,
         PrivateKey             signerKey,
         String                 algorithmName, 
         CAReferenceField       caRef, 
         HolderReferenceField   holderRef, 
         AuthorizationRoleEnum  authRole,
         AccessRightEnum        rights,
         Date                   validFrom,
         Date                   validTo,
         String                 provider ) 
   throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, ConstructionException {

      CVCPublicKey cvcPublicKey = KeyFactory.createInstance(publicKey, algorithmName, authRole);
      
      // Create the CVCertificateBody
      CVCertificateBody body = new CVCertificateBody(
            caRef, 
            cvcPublicKey,
            holderRef,
            authRole,
            rights,
            validFrom,
            validTo );

      CVCertificate cvc = new CVCertificate(body);
      
      // Perform signing
      Signature signature = Signature.getInstance(AlgorithmUtil.convertAlgorithmNameToCVC(algorithmName), provider);
      signature.initSign(signerKey);
      signature.update(cvc.getTBS());
      byte[] signdata = signature.sign();

      // Save the signature and return the certificate
      cvc.setSignature(signdata);
      return cvc;
   }

   /**
    * Generates a CVC-request without an outer signature using BouncyCastle as signature provider
    * @param keyPair
    * @param algorithmName
    * @param holderRef
    * @return
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws NoSuchProviderException
    * @throws InvalidKeyException
    * @throws SignatureException
    */
   public static CVCertificate createRequest(
         KeyPair               keyPair, 
         String                algorithmName, 
         HolderReferenceField  holderRef ) 
   throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, ConstructionException{
      return createRequest(keyPair, algorithmName, holderRef, "BC");
   }

   /**
    * Same as above except that signature provider is an argument
    * @param keyPair
    * @param algorithmName
    * @param holderRef
    * @param signProvicer
    * @return
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws NoSuchProviderException
    * @throws InvalidKeyException
    * @throws SignatureException
    * @throws ConstructionException
    */
   public static CVCertificate createRequest(
         KeyPair               keyPair, 
         String                algorithmName, 
         HolderReferenceField  holderRef,
         String                signProvicer ) 
   throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, ConstructionException{
      return createRequest(keyPair, algorithmName, null, holderRef, signProvicer);
   }

   /**
    * Generates a CVC-request without an outer signature using BouncyCastle as signature provider, taking
    * Certificate Authority Reference as argument.
    * @param keyPair
    * @param algorithmName
    * @param holderRef
    * @param caRef
    * @return
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws NoSuchProviderException
    * @throws InvalidKeyException
    * @throws SignatureException
    */
   public static CVCertificate createRequest(
         KeyPair               keyPair, 
         String                algorithmName,
         CAReferenceField      caRef,
         HolderReferenceField  holderRef )  
   throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, ConstructionException{
      return createRequest(keyPair, algorithmName, caRef, holderRef, "BC");
   }

   /**
    * Same as above except that signature provider is also an argument
    * @param keyPair
    * @param algorithmName
    * @param caRef
    * @param holderRef
    * @param signProvicer
    * @return
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws NoSuchProviderException
    * @throws InvalidKeyException
    * @throws SignatureException
    * @throws ConstructionException
    */
   public static CVCertificate createRequest(
         KeyPair               keyPair, 
         String                algorithmName,
         CAReferenceField      caRef,
         HolderReferenceField  holderRef,
         String                signProvicer )  
   throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, ConstructionException{
      CVCPublicKey cvcPublicKey = KeyFactory.createInstance(keyPair.getPublic(), algorithmName, null);

      // Create the Request Body (which is a simplified CVCertificateBody)
      CVCertificateBody reqBody = new CVCertificateBody(
            caRef,
            cvcPublicKey,
            holderRef );
      
      CVCertificate cvc = new CVCertificate(reqBody);
      
      // Perform the signing
      Signature innerSign = Signature.getInstance(AlgorithmUtil.convertAlgorithmNameToCVC(algorithmName), signProvicer);
      innerSign.initSign(keyPair.getPrivate());
      innerSign.update(cvc.getTBS());
      byte[] signdata = innerSign.sign();

      // Create and return the CVCRequest (which is an instance of CVCertificate)
      cvc.setSignature(signdata);
      return cvc;
   }


   /**
    * Generates a CVCAuthenticatedRequest using BouncyCastle as signature provider
    * @param cvcRequest
    * @param keyPair
    * @param algorithmName
    * @param caRef Should be the same as caRef in the supplied cvcRequest but with an incremented sequence number
    * @return
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws NoSuchProviderException
    * @throws InvalidKeyException
    * @throws SignatureException
    */
   public static CVCAuthenticatedRequest createAuthenticatedRequest(
         CVCertificate     cvcRequest,
         KeyPair           keyPair, 
         String            algorithmName,
         CAReferenceField  caRef ) 
   throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, ConstructionException {
      return createAuthenticatedRequest(cvcRequest, keyPair, algorithmName, caRef, "BC");
   }

   /**
    * Same as above except that signature provider is an argument
    * @param cvcRequest
    * @param keyPair
    * @param algorithmName
    * @param caRef
    * @param signProvider
    * @return
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws NoSuchProviderException
    * @throws InvalidKeyException
    * @throws SignatureException
    * @throws ConstructionException
    */
   public static CVCAuthenticatedRequest createAuthenticatedRequest(
         CVCertificate     cvcRequest,
         KeyPair           keyPair, 
         String            algorithmName,
         CAReferenceField  caRef, 
         String            signProvider )
   throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, ConstructionException {

      CVCAuthenticatedRequest authRequest = new CVCAuthenticatedRequest(cvcRequest, caRef);

      // Perform the signing
      Signature outerSign = Signature.getInstance(AlgorithmUtil.convertAlgorithmNameToCVC(algorithmName), signProvider);
      outerSign.initSign(keyPair.getPrivate());
      outerSign.update(authRequest.getTBS());
      byte[] signdata = outerSign.sign();

      // Create and return the CVCAuthenticatedRequest
      authRequest.setSignature(signdata);
      return authRequest;
   }

}
