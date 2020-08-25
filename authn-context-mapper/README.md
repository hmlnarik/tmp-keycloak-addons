Mapper for SAML clients to set AuthnContextClassRef
===================================================

This is a mapper to add a Keycloak 9+ / SSO 7.4 mapper to a SAML client that updates SAML Response with AuthnContextClassRef as specified in the configuration.

Compilation
-----------
Run the following:

    mvn clean install

Installation
------------
Copy the `target/authn-context-mapper-1.0-SNAPSHOT.jar` to `standalone/deployments` in the Keycloak / RHSSO installation directory.

Usage
-----
Go to the chosen SAML client, select `Mappers` tab, and add the mapper called `Customize AuthnContext`. Specify the desired `AuthnContextClassRef` in the `AuthnContextClassRef` parameter. Note that this parameter must be a URI understood by the counterparty, e.g. `urn:oasis:names:tc:SAML:2.0:ac:classes:Password`.

Note that this mapper only works if there is `Include AuthnStatement` switch enabled in the basic settings of the SAML client.
