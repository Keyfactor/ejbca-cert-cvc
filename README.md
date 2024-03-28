<!--EJBCA Community logo -->
<a href="https://ejbca.org">
    <img src=".github/images/community-ejbca.png?raw=true)" alt="EJBCA logo" title="EJBCA" height="70" />
</a>
<!--EJBCA Enterprise logo -->
<a href="https://www.keyfactor.com/products/ejbca-enterprise/">
    <img src=".github/images/keyfactor-ejbca-enterprise.png?raw=true)" alt="EJBCA logo" title="EJBCA" height="70" />
</a>

# EJBCA Cert CVC

EJBCA Cert CVC is a Java library for parsing, creating, and using cv certificates defined for Extended Access Control (EAC) in BSI TR-03110.
It is primarily used for ePassports and eIDs. 

## Get Started

### Dependencies

Cert-cvc depends on the Bouncycastle JCE provider (www.bouncycastle.org).
The provider is used for DER encoding and some crypto stuff. 

### Building and testing with Maven

You build, and run JUnit tests with maven.

mvn package

will build, run tests and place the artefact in 'target'.

### Using

There are example and test code which demonstrates the use of cert-cvc.jar, see here: 
* [Code examples](src/main/java/org/ejbca/cvc/example)
* [Test code (JUnit tests)](src/test).

## Community Support
In the [Keyfactor Community](https://www.keyfactor.com/community/), we welcome contributions. 

The Community software is open-source and community-supported, meaning that **no SLA** is applicable.

* To report a problem or suggest a new feature, go to [Issues](../../issues).
* If you want to contribute actual bug fixes or proposed enhancements, see the [Contributing Guidelines](CONTRIBUTING.md) and go to [Pull requests](../../pulls).

## Commercial Support

Commercial support is available for [EJBCA Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/).

## License
For license information, see [LICENSE](LICENSE). 

## Related Projects
See all [Keyfactor EJBCA GitHub projects](https://github.com/orgs/Keyfactor/repositories?q=ejbca). 
