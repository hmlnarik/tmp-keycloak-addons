/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.custom.authn.context.mapper;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.dom.saml.v2.assertion.AuthnContextClassRefType;
import org.keycloak.dom.saml.v2.assertion.AuthnContextType;
import org.keycloak.dom.saml.v2.assertion.AuthnContextType.AuthnContextTypeSequence;
import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.saml.mappers.AbstractSAMLProtocolMapper;
import org.keycloak.protocol.saml.mappers.SAMLLoginResponseMapper;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * SAML mapper to add a audience restriction into the assertion, to another
 * client (clientId) or to a custom URI. Only one URI is added, clientId
 * has preference over the custom value (the class maps OIDC behavior).
 *
 * @author rmartinc
 */
public class SAMLAuthnContextProtocolMapper extends AbstractSAMLProtocolMapper implements SAMLLoginResponseMapper {

    protected static final Logger logger = Logger.getLogger(SAMLAuthnContextProtocolMapper.class);

    public static final String PROVIDER_ID = "saml-authn-context-mapper";

    public static final String AUTHN_CONTEXT_CLASS_REF_CATEGORY = "Specify AuthnContextClassRef in SAML Response mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    public static final String AUTHN_CONTEXT_CLASS_REF = "included.custom.audience";
    private static final String AUTHN_CONTEXT_CLASS_REF_LABEL = "AuthnContextClassRef";
    private static final String AUTHN_CONTEXT_CLASS_REF_HELP_TEXT = "Value of the single AuthnContextClassRef in the response";

    static {
        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(AUTHN_CONTEXT_CLASS_REF);
        property.setLabel(AUTHN_CONTEXT_CLASS_REF_LABEL);
        property.setHelpText(AUTHN_CONTEXT_CLASS_REF_HELP_TEXT);
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Customize AuthnContext";
    }

    @Override
    public String getDisplayCategory() {
        return AUTHN_CONTEXT_CLASS_REF_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Add specified AuthnContextClassRef to the AuthnContext in the AuthnStatement.";
    }

    protected static AuthnContextTypeSequence locateAuthnContextClassRefType(ResponseType response) {
        try {
            return response.getAssertions().get(0).getAssertion()
                    .getStatements().stream()
                    .filter(AuthnStatementType.class::isInstance)
                    .map(AuthnStatementType.class::cast)
                    .map(AuthnStatementType::getAuthnContext)
                    .map(AuthnContextType::getSequence)
                    .findFirst().orElse(null);
        } catch (NullPointerException | IndexOutOfBoundsException e) {
            logger.warn("Invalid SAML ResponseType to add the audience restriction", e);
            return null;
        }
    }

    @Override
    public ResponseType transformLoginResponse(ResponseType response,
            ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        String authnContextClassRef = mappingModel.getConfig().get(AUTHN_CONTEXT_CLASS_REF);

        if (authnContextClassRef != null && !authnContextClassRef.trim().isEmpty()) {
            AuthnContextTypeSequence acts = locateAuthnContextClassRefType(response);
            if (acts != null) {
                logger.debugf("setting AuthnContextClassRef: %s", authnContextClassRef);
                try {
                    acts.setClassRef(new AuthnContextClassRefType(URI.create(authnContextClassRef)));
                } catch (IllegalArgumentException e) {
                    logger.warnf(e, "Invalid URI syntax for AuthnContextClassRef: %s", authnContextClassRef);
                }
            }
        }
        return response;
    }

}
