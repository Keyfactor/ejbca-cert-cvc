package org.ejbca.cvc;

public class UnknownAuthorizationRole implements AuthorizationRole {
   private final byte value;
   
   public UnknownAuthorizationRole( byte value ) {
      this.value = value;
   }

   @Override
   public byte getValue() {
      return value;
   }
   
   @Override
   public String name() {
      return "UNKNOWN";
   }
   
   @Override
   public String toString() {
      return "UnknownRole(" + Integer.toString( value & 0xFF, 16 ).toUpperCase() + ")";
   }
   
   @Override
   public boolean isCVCA() {
      return false;
   }
   
   @Override
   public boolean isDV() {
      return false;
   }
   
   @Override
   public boolean isDomesticDV() {
      return false;
   }
   
   @Override
   public boolean isForeignDV() {
      return false;
   }
   
   @Override
   public boolean isAccreditationBodyDV() {
      return false;
   }
   
   @Override
   public boolean isCertificationServiceProviderDV() {
      return false;
   }
   
   @Override
   public boolean isIS() {
      return false;
   }
   
   @Override
   public boolean isAuthenticationTerminal() {
      return false;
   }
   
   @Override
   public boolean isSignatureTerminal() {
      return false;
   }
}
