# Description

cert-cvc is a java library for parsing, creating, and using cv certificates defined for Extended Access Control (EAC) in BSI TR-03110.
It is primarily used for ePassports and eIDs. 

# Dependencies

Cert-cvc depends on the Bouncycastle JCE provider (www.bouncycastle.org).
The provider is used for DER encoding and some crypto stuff. 

Bouncycastle is licensed under an MIT license.

# Building and testing with Maven

You build, and run JUnit tests with maven.

mvn package

will build, run tests and place the artefact in 'target'.

# Using

There are example and test code which demonstrates the use of cert-cvc.jar. 
Some examples are under src/main/java/org/ejbca/cvc/example, and the test code (JUnit tests) are under 
src/test.
