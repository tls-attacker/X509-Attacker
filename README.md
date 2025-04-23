# X.509-Attacker

![licence](https://img.shields.io/badge/License-Apachev2-brightgreen.svg)
[![Build Status](http://hydrogen.cloud.nds.rub.de/buildStatus/icon.svg?job=X509-Attacker)](http://hydrogen.cloud.nds.rub.de/job/X509-Attacker/)

X.509-Attacker is a tool based on ASN.1-Attacker for creating arbitrary certificates; including especially invalid and
malformed certificates.

# Installation

In order to compile and use X.509-Attacker, you need to have Java and Maven installed. On Ubuntu you can install Maven by
running:

```bash
$ sudo apt-get install maven
```

X.509-Attacker currently needs Java JDK 21 to run. If you have the correct Java version you can install
X.509-Attacker as follows.

```bash
$ git clone https://github.com/tls-attacker/X509-Attacker.git
$ cd X509-Attacker
$ mvn clean install
```

If you want to use this project as a dependency, you do not have to compile it yourself and can include it in your pom
.xml as follows.

```xml
<dependency>
    <groupId>de.rub.nds</groupId>
    <artifactId>x509-attacker</artifactId>
    <version>4.0.0</version>
</dependency>
```

# Acknowledgements

The framework was initially developed by Nils Kafka (nils.kafka@ruhr-uni-bochum.de) during his master thesis.
Extended by Joshua Waldner.

In 2023, the project was rewritten by Robert Merget (Technology Innovation Institute).

# Projects

This framework is used by TLS-Attacker (https://github.com/tls-attacker/TLS-Attacker/)
