package de.rub.nds.x509attacker;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;
import de.rub.nds.x509attacker.asn1.parser.StructureParser;
import de.rub.nds.x509attacker.asn1.parser.converters.BasicConverter;
import de.rub.nds.x509attacker.asn1.parser.converters.ConverterException;

import java.util.Base64;
import java.util.List;

public class MainSimpleAsn1Parser {
    public static void main(String[] args) {
        byte[] asn1 = Base64.getDecoder().decode("MIID2zCCAsOgAwIBAgIJAKScsvejC8mGMA0GCSqGSIb3DQEBBQUAMIGDMQswCQYDVQQGEwJERTEMMAoGA1UECAwDTlJXMQ8wDQYDVQQHDAZCb2NodW0xDDAKBgNVBAoMA1JVQjEMMAoGA1UECwwDTkRTMRcwFQYDVQQDDA53d3cubmRzLnJ1Yi5kZTEgMB4GCSqGSIb3DQEJARYRb2ZmaWNlQG5kcy5ydWIuZGUwHhcNMTkwMzA2MTcyODM4WhcNMjAwMzEwMTcyODM4WjCBgzELMAkGA1UEBhMCREUxDDAKBgNVBAgMA05SVzEPMA0GA1UEBwwGQm9jaHVtMQwwCgYDVQQKDANSVUIxDDAKBgNVBAsMA05EUzEXMBUGA1UEAwwOd3d3Lm5kcy5ydWIuZGUxIDAeBgkqhkiG9w0BCQEWEW9mZmljZUBuZHMucnViLmRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwfOYu9F2iXdJkqBZNlikYbGevqVIXVwP3L6/AA8B92zNyLLB/b1MvRf/qBUdl7hXepdLKp8KZCLuVd+lHG/gIEvnqwNIzmMfZav9s9F8yn8vUTp1UhHwfB4TpOm/N8wimKpueNyhtf9ayoQGwRui7Wgo9vC2vXrNPXyURdhdIOZIvCGxCc6b00X/KgS+ZkOGEW6FimoHXBxx/zWfla24dyrMstfewGkE49VSQqX4UvgjFOpg1Q/T33PutotE0zaCuhXCV2VrGhwJFsbF8e5o4/X//osI+DGKbmtq3ZG/+2GLWVOwnM1qHAy2sVeVe//VB2BoiBB0yQTnB3lMHKDAfwIDAQABo1AwTjAdBgNVHQ4EFgQURq9Q2+kNgnA4ADIg4zbu8WvIQ1AwHwYDVR0jBBgwFoAURq9Q2+kNgnA4ADIg4zbu8WvIQ1AwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAwD6ycE5lLlLR3Zhfi7T9TC+XNZUCleA1LP92TJWHWI0RSRKY2g1lFebhEKZNaYqXSkVzh5foFfqqFPJWzVl4rBrWrQR8dzFI+R6mxXgs/5BmCjzN08yygTTdv3c7NuyvuicUcD5FOO2rHyueObIL86elx82c/JwpdUXBqGykCsF+2FKq3uJVvCFMSGrwwGibyk/h0QVriRNYasm4peNSxU3QJeXxiQ4gueZi5pe5uNxAsGlddfQgzUxMJau92UdEOH/oCZlR0ItCoxlqQy+a3CrV8oDHZ/xa3H+M8Ujlmvjw+4kcI21+S/IhVh71JGL15IqnRcQgnn+j2MCRh0Dhbg==");
        StructureParser structureParser = new StructureParser(asn1);
        List<StructureParser.FieldPrototype> prototypes = structureParser.parse();
        BasicConverter converter = new BasicConverter(null, prototypes);
        try {
            List<Asn1RawField> fields = converter.convert();
            int i = 0;
        } catch (ConverterException e) {
            e.printStackTrace();
        }
    }
}
