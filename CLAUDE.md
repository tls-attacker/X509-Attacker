# X509-Attacker Development Guide

## Build/Test Commands
```bash
# Build project
mvn clean install

# Run all tests
mvn test

# Run a specific test class
mvn test -Dtest=X509CertificateTest

# Run a specific test method
mvn test -Dtest=X509CertificateTest#testGetCommonName

# Code format check
mvn spotless:check

# Code format fix
mvn spotless:apply
```

## Code Style
- **Java Version**: JDK 21
- **Formatting**: Google Java Format (AOSP style)
- **Indentation**: 4 spaces
- **Imports**: Organized and unused imports removed
- **Error Handling**: Use specific exceptions with informative messages
- **Naming**: 
  - Classes: PascalCase (e.g., X509CertificateChain)
  - Methods/Variables: camelCase
  - Constants: UPPER_CASE
- **Testing**: JUnit 5 with descriptive test names

## Project Structure
X.509-Attacker is based on ASN.1-Attacker for creating certificates, including invalid/malformed ones.