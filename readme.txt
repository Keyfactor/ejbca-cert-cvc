Dependencies
------------
Cert-cvc depends on the Bouncycastle JCE provider (www.bouncycastle.org).
The provider is used for DER encoding and some crypto stuff. 
The version available in svn is 1.41, but cert-cvc will work just as fine with other versions that
are API compatible.

Bouncycastle is licensed under a BSD-like license.

Building
--------
Having java and ant installed, simply run 'ant' to build the cert-cvc jar, cert-cvc.jar will be placed
in the root directory.

Using
-----
There are example and test code which demonstrates the use of cert-cvc.jar. 
Some examples are under src/main/java/org/ejbca/cvc/example, and the test code (JUnit tests) are under 
src/test.
   