# Description
cert-cvc is a java library for parsing, creating, and using cv certificates defined for Extended Access Control (EAC) in BSI TR-03110.
It is primarily used for ePassports and eIDs. 

# Dependencies
------------
Cert-cvc depends on the Bouncycastle JCE provider (www.bouncycastle.org).
The provider is used for DER encoding and some crypto stuff. 

Bouncycastle is licensed under an MIT license.

# Building
--------
Having java and ant installed, simply run 'ant' to build the cert-cvc jar, cert-cvc.jar will be placed
in the root directory.

Note that the produced cert-cvc.jar is built against the BouncyCastle version included in the lib directory. 
To build against a different BouncyCastle version you must replace the bc jar in lib.

# Using
-----
There are example and test code which demonstrates the use of cert-cvc.jar. 
Some examples are under src/main/java/org/ejbca/cvc/example, and the test code (JUnit tests) are under 
src/test.
