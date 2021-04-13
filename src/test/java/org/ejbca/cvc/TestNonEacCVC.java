package org.ejbca.cvc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class TestNonEacCVC extends TestCase implements CVCTest {
   static final String CC_ROLE_SC_HSM = "1.3.6.1.4.1.24991.3.1.1";
   
   protected void setUp() throws Exception {
      // Install Bouncy Castle as security provider
      Security.addProvider( new BouncyCastleProvider() );
   }
   
   protected void tearDown() throws Exception {
      // Uninstall BC
      Security.removeProvider( "BC" );
   }
   
   public void test_dontFailOnUnknownChat() throws Exception {
      byte[] rawCvc = Hex.decode(
              "7F218201B47F4E82016C5F290100420E44455352434143433130303030317F4982011D060A04007F000702020202038120A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E537782207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9832026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B68441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F0469978520A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A78641046D025A8026CDBA245F10DF1B72E9880FFF746DAB40A43A3D5C6BEBF27707C30F6DEA72430EE3287B0665C1EAA6EAA4FA26C46303001983F82BD1AA31E03DA0628701015F200E44455352434143433130303030317F4C10060B2B0601040181C31F0301015301C05F25060102010100095F24060302010100085F37409DBB382B1711D2BAACB0C623D40C6267D0B52BA455C01F56333DC9554810B9B2878DAF9EC3ADA19C7B065D780D6C9C3C2ECEDFD78DEB18AF40778ADF89E861CA" );

      CVCertificate cvc = CertificateParser.parseCertificate( rawCvc );

      assertNotNull( cvc );
      assertAuthorization(cvc, CC_ROLE_SC_HSM, (byte)0xC0, Hex.decode( "C0" ));
   }
   
   public void test_constructWithUnknownChat() throws Exception {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance( "EC" );
      KeyPair keyPair = keyGen.generateKeyPair();

      CAReferenceField car = new CAReferenceField( "DE", "TEST", "00001" );
      HolderReferenceField chr = new HolderReferenceField( "DE", "TEST", "00001" );

      AuthorizationRole role = new AuthorizationRoleRawValue( (byte)0xC0 );
      AccessRights rights = new AccessRightsRawValue( new byte[] { role.getValue() } );

      CVCAuthorizationTemplate chat = new CVCAuthorizationTemplate( role, rights, CC_ROLE_SC_HSM );

      String algorithm = "SHA256withECDSA";
      CVCPublicKey cvcPublicKey = KeyFactory.createInstance( keyPair.getPublic(), algorithm, role );
      CVCertificateBody cvcBody = new CVCertificateBody( car, cvcPublicKey, chr, chat, new Date(), new Date() );

      CVCertificate cvCertificate = CertificateGenerator.createCertificate( keyPair.getPrivate(), algorithm, cvcBody, BouncyCastleProvider.PROVIDER_NAME );

      assertNotNull( cvCertificate );
      assertAuthorization(cvCertificate, CC_ROLE_SC_HSM, (byte)0xC0, Hex.decode( "C0" ));
   }
   
   private static void assertAuthorization(CVCertificate cvc, String oid, byte role, byte[] rights) throws Exception {
      CVCAuthorizationTemplate chat = cvc.getCertificateBody().getAuthorizationTemplate();
      assertEquals( oid, chat.getObjectIdentifier());

      AuthorizationField authorizationField = chat.getAuthorizationField();
      assertTrue( authorizationField.getAccessRights() instanceof AccessRightsRawValue );
      assertTrue( authorizationField.getAuthRole() instanceof AuthorizationRoleRawValue );

      assertEquals( authorizationField.getAuthRole().getValue(), role);
      assertEquals( Hex.toHexString( authorizationField.getAccessRights().getEncoded() ), Hex.toHexString( rights ));
   }
}
