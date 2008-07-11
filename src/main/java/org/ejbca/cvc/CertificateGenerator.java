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
 * Klass f�r att generera CV-certifikat samt -request
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 *
 */
public class CertificateGenerator {

   // Klassen beh�ver inte instansieras
   private CertificateGenerator(){
   }

   /**
    * Genererar ett nytt CVCertificate giltigt 3 m�nader fr�n idag, hash-algoritm 'SHA1withRSA' samt
    * AuthorizationRoleEnum = IS.
    * 
    *   TODO: Flytta metoden till test-klasserna!
    * 
    * @param keyPair
    * @param caRef
    * @param holderRef
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
         HolderReferenceField  holderRef ) 
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
            "SHA1withRSA", 
            caRef, 
            holderRef, 
            AuthorizationRoleEnum.IS,
            AccessRightEnum.READ_ACCESS_DG3_AND_DG4,
            validFrom, 
            validTo, 
            "BC" );
   }


   /**
    * Genererar ett nytt CVCertificate
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

      CVCPublicKey cvcPublicKey = KeyFactory.createInstance(publicKey, algorithmName);
      
      // Skapa en CVCertificateBody
      CVCertificateBody body = new CVCertificateBody(
            caRef, 
            cvcPublicKey,
            holderRef,
            authRole,
            rights,
            validFrom,
            validTo );

      // Plocka ut datat att signera
      TBSData tbs = TBSData.getInstance(body);
      
      // Utf�r signering
      Signature signature = Signature.getInstance(algorithmName, provider);
      signature.initSign(signerKey);
      signature.update(tbs.getEncoded());
      byte[] signdata = signature.sign();

      // Nu kan en instans av certifikatet skapas
      return new CVCertificate(body, signdata);
   }

   /**
    * Skapar ett cvc-request utan yttre signatur
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
    * Som ovan men d�r �ven signaturprovider kan anges.
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
    * Skapar ett cvc-request utan yttre signatur d�r Certificate Authority Reference
    * kan anges.
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
    * Som ovan men d�r �ven signaturprovider kan anges.
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
      CVCPublicKey cvcPublicKey = KeyFactory.createInstance(keyPair.getPublic(), algorithmName);

      /* Certificate Authority Reference ska ha samma v�rden som Certificate Holder Reference
       * eftersom detta blir ett self-signed certifikat.
       */
      if( caRef==null ){
         caRef = new CAReferenceField(holderRef.getCountry(), holderRef.getMnemonic(), holderRef.getSequence());
      }

      CVCertificateBody reqBody = new CVCertificateBody(
            caRef,          // CA ref
            cvcPublicKey,   // public key
            holderRef );    // holder ref
      
      // Plocka ut datat att signera
      TBSData tbs = TBSData.getInstance(reqBody);
      
      // Utf�r inre signering
      Signature innerSign = Signature.getInstance(algorithmName, signProvicer);
      innerSign.initSign(keyPair.getPrivate());
      innerSign.update(tbs.getEncoded());
      byte[] signdata = innerSign.sign();

      // Skapa CVCRequest
      return new CVCertificate(reqBody, signdata);
   }


   /**
    * Skapar instans av CVCAuthenticatedRequest
    * @param cvcRequest
    * @param keyPair
    * @param algorithmName
    * @param caRef Ska vara samma som caRef i cvcRequest men med uppr�knat sekvensnummer
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
    * Samma som ovan men d�r �ven signature provider kan anges.
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

      // Utf�r yttre signering
      TBSData reqTbs = TBSData.getInstance(cvcRequest);

      Signature outerSign = Signature.getInstance(algorithmName, signProvider);
      outerSign.initSign(keyPair.getPrivate());
      outerSign.update(reqTbs.getEncoded());
      byte[] signdata = outerSign.sign();

      // Skapa autenticerat request
      return new CVCAuthenticatedRequest(cvcRequest, caRef, signdata);
   }
}
