/*
 * Copyright (c) 2016 by European Commission
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 * This product combines work with different licenses. See the "NOTICE" text
 * file for details on the various modules and licenses.
 * The "NOTICE" text file is part of the distribution. Any derivative works
 * that you distribute must include a readable copy of the "NOTICE" text file.
 *
 */

package eu.eidas.auth.engine.xml.opensaml;

import java.util.Collections;
import java.util.Map;

import javax.annotation.Nonnull;

import com.google.common.collect.ImmutableSet;

import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextDecl;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.OneTimeUse;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.SubjectLocality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.eidas.auth.commons.EidasErrorKey;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.AttributeValue;
import eu.eidas.auth.commons.attribute.AttributeValueMarshaller;
import eu.eidas.auth.commons.attribute.AttributeValueMarshallingException;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.protocol.IAuthenticationRequest;
import eu.eidas.auth.commons.protocol.impl.SamlNameIdFormat;
import eu.eidas.auth.engine.AbstractProtocolEngine;
import eu.eidas.auth.engine.core.SAMLExtensionFormat;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;

/**
 * AssertionUtil
 *
 * @since 1.1
 */
public final class AssertionUtil {

    private static final String FAILURE_SUBJECT_NAME_ID = "NotAvailable";
    /**
     * The Constant LOG.
     */
    private static final Logger LOG = LoggerFactory.getLogger(AssertionUtil.class);


    private AssertionUtil() {
        // empty constructor
    }

    /**
     * Generates the assertion for the response.
     *
     * @param ipAddress    the IP address.
     * @param request      the request for which the response is prepared
     * @param notOnOrAfter the not on or after
     * @return the assertion
     * @throws EIDASSAMLEngineException the EIDASSAML engine exception
     */
    public static final Assertion generateResponseAssertion(boolean isFailure,
                                                            String ipAddress,
                                                            IAuthenticationRequest request,
                                                            Issuer responseIssuer,
                                                            ImmutableAttributeMap attributeMap,
                                                            DateTime notOnOrAfter,
                                                            String formatEntity,
                                                            String responder,
                                                            SAMLExtensionFormat extensionFormat,
                                                            boolean isOneTimeUse) throws EIDASSAMLEngineException {
        LOG.trace("Generate Assertion.");

        // Mandatory
        LOG.trace("Generate Issuer to Assertion");
        Issuer issuerAssertion = BuilderFactoryUtil.generateIssuer();
        issuerAssertion.setValue(responseIssuer.getValue());

        // Format Entity Optional
        issuerAssertion.setFormat(formatEntity);

        Assertion assertion =
                BuilderFactoryUtil.generateAssertion(SAMLVersion.VERSION_20, SAMLEngineUtils.generateNCName(),
                                                     SAMLEngineUtils.getCurrentTime(), issuerAssertion);

        // Subject is mandatory in non failure responses, in some cases it is available for failure also
        addSubjectToAssertion(isFailure, assertion, request, attributeMap, notOnOrAfter, ipAddress, responder, extensionFormat);

        // Conditions that MUST be evaluated when assessing the validity of
        // and/or when using the assertion.
        Conditions conditions = generateConditions(SAMLEngineUtils.getCurrentTime(), notOnOrAfter, request.getIssuer(), isOneTimeUse);

        assertion.setConditions(conditions);

        LOG.trace("Generate Authentication Statement.");
        AuthnStatement eidasAuthnStat = generateAuthStatement(ipAddress);
        assertion.getAuthnStatements().add(eidasAuthnStat);

        return assertion;
    }

    private static void addSubjectToAssertion(boolean isFailure,
                                              Assertion assertion,
                                              IAuthenticationRequest request,
                                              ImmutableAttributeMap attributeMap,
                                              DateTime notOnOrAfter,
                                              String ipAddress,
                                              String responder, SAMLExtensionFormat extensionFormat) throws EIDASSAMLEngineException {
        Subject subject = BuilderFactoryUtil.generateSubject();

        NameID nameId = getNameID(isFailure, request.getNameIdFormat(), attributeMap, responder, extensionFormat);
        subject.setNameID(nameId);

        // Mandatory if urn:oasis:names:tc:SAML:2.0:cm:bearer.
        // Optional in other case.
        LOG.trace("Generate SubjectConfirmationData.");
        SubjectConfirmationData dataBearer =
                BuilderFactoryUtil.generateSubjectConfirmationData(SAMLEngineUtils.getCurrentTime(),
                                                                   request.getAssertionConsumerServiceURL(),
                                                                   request.getId());

        // Mandatory if urn:oasis:names:tc:SAML:2.0:cm:bearer.
        // Optional in other case.
        LOG.trace("Generate SubjectConfirmation");
        SubjectConfirmation subjectConf =
                BuilderFactoryUtil.generateSubjectConfirmation(SubjectConfirmation.METHOD_BEARER, dataBearer);

        SubjectConfirmationData subjectConfirmationData = subjectConf.getSubjectConfirmationData();
        if (SubjectConfirmation.METHOD_BEARER.equals(subjectConf.getMethod())) {
            // ipAddress Mandatory if method is Bearer.

            if (StringUtils.isBlank(ipAddress)) {
                LOG.info(AbstractProtocolEngine.SAML_EXCHANGE, "BUSINESS EXCEPTION : ipAddress is null or empty");
                throw new EIDASSAMLEngineException(EidasErrorKey.INTERNAL_ERROR.errorCode(),
                        EidasErrorKey.INTERNAL_ERROR.errorCode(),
                        "ipAddress is null or empty");
            }
            subjectConfirmationData.setAddress(ipAddress.trim());
        }

        subjectConfirmationData.setRecipient(request.getAssertionConsumerServiceURL());
        subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);

        // The SAML 2.0 specification allows multiple SubjectConfirmations
        subject.getSubjectConfirmations().addAll(Collections.singletonList(subjectConf));

        // Mandatory if not failure
        assertion.setSubject(subject);
    }

    private static NameID getNameID(boolean isFailure, String requestFormat, ImmutableAttributeMap attributeMap, String responder, SAMLExtensionFormat extensionFormat)
            throws EIDASSAMLEngineException {
        NameID nameId;
        String nameQualifier = responder;
        String format;
        String spNameQualifier = "";
        String nameIdValue;
        LOG.trace("Generate NameID");

        if (isFailure) {
            format = SamlNameIdFormat.UNSPECIFIED.getNameIdFormat();
            nameIdValue = FAILURE_SUBJECT_NAME_ID;
        } else {
            // Mandatory to be verified
            // String format = NameID.UNSPECIFIED
            // specification: 'SAML:2.0' exist
            // opensaml: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
            // opensaml  "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"
            format = requestFormat;
            if (null == format) {
                format =
                        SAMLExtensionFormat.EIDAS10 == extensionFormat ? SamlNameIdFormat.PERSISTENT
                                .getNameIdFormat() : SamlNameIdFormat.UNSPECIFIED.getNameIdFormat();
            }
            nameIdValue = getUniquenessIdentifier(attributeMap);
        }

        nameId = BuilderFactoryUtil.generateNameID(nameQualifier, format, spNameQualifier);
        nameId.setValue(nameIdValue);
        return nameId;
    }

    private static String getUniquenessIdentifier(@Nonnull ImmutableAttributeMap attributeMap)
            throws EIDASSAMLEngineException {
        for (final Map.Entry<AttributeDefinition<?>, ImmutableSet<? extends AttributeValue<?>>> entry : attributeMap.getAttributeMap()
                .entrySet()) {
            AttributeDefinition<?> attributeDefinition = entry.getKey();
            ImmutableSet<? extends AttributeValue<?>> values = entry.getValue();
            if (attributeDefinition.isUniqueIdentifier() && !values.isEmpty()) {
                AttributeValueMarshaller<?> attributeValueMarshaller =
                        attributeDefinition.getAttributeValueMarshaller();
                try {
                    return attributeValueMarshaller.marshal((AttributeValue)values.iterator().next());
                } catch (AttributeValueMarshallingException e) {
                    LOG.error("BUSINESS EXCEPTION : Invalid Attribute Value " + e, e);
                    throw new EIDASSAMLEngineException(EidasErrorKey.INTERNAL_ERROR.errorCode(),
                            EidasErrorKey.INTERNAL_ERROR.errorCode(), e);
                }
            }
        }
        String message = "Unique Identifier not found: " + attributeMap;
        LOG.info("BUSINESS EXCEPTION : " + message);
        throw new EIDASSAMLEngineException(EidasErrorKey.INTERNAL_ERROR.errorCode(),
                EidasErrorKey.INTERNAL_ERROR.errorCode(), message);
    }

    /**
     * Generate conditions that MUST be evaluated when assessing the validity of and/or when using the assertion.
     *
     * @param notBefore    the not before
     * @param notOnOrAfter the not on or after
     * @param audienceURI  the audience URI.
     * @return the conditions
     */
    private static Conditions generateConditions(DateTime notBefore, DateTime notOnOrAfter, String audienceURI, boolean isOneTimeUse)
            throws EIDASSAMLEngineException {
        LOG.trace("Generate conditions.");
        Conditions conditions = (Conditions) BuilderFactoryUtil.buildXmlObject(Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore(notBefore);
        conditions.setNotOnOrAfter(notOnOrAfter);

        AudienceRestriction restrictions =
                (AudienceRestriction) BuilderFactoryUtil.buildXmlObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        Audience audience = (Audience) BuilderFactoryUtil.buildXmlObject(Audience.DEFAULT_ELEMENT_NAME);
        audience.setAudienceURI(audienceURI);

        restrictions.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(restrictions);

        if (isOneTimeUse) {
            OneTimeUse oneTimeUse = (OneTimeUse) BuilderFactoryUtil.buildXmlObject(OneTimeUse.DEFAULT_ELEMENT_NAME);
            conditions.getConditions().add(oneTimeUse);
        }
        return conditions;
    }

    /**
     * Generate authentication statement.
     *
     * @param ipAddress the IP address
     * @return the authentication statement
     */
    private static AuthnStatement generateAuthStatement(String ipAddress) throws EIDASSAMLEngineException {
        LOG.trace("Generate authenticate statement.");
        SubjectLocality subjectLocality = BuilderFactoryUtil.generateSubjectLocality(ipAddress);

        AuthnContext authnContext = (AuthnContext) BuilderFactoryUtil.buildXmlObject(AuthnContext.DEFAULT_ELEMENT_NAME);

        AuthnContextDecl authnContextDecl =
                (AuthnContextDecl) BuilderFactoryUtil.buildXmlObject(AuthnContextDecl.DEFAULT_ELEMENT_NAME);

        authnContext.setAuthnContextDecl(authnContextDecl);

        AuthnStatement authnStatement = BuilderFactoryUtil.generateAuthnStatement(new DateTime(), authnContext);

        // Optional
        authnStatement.setSessionIndex(null);
        authnStatement.setSubjectLocality(subjectLocality);

        return authnStatement;
    }
}
