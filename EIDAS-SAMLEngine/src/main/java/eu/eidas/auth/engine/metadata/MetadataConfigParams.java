/*
 * Copyright (c) 2016 by European Commission
 *
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
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
package eu.eidas.auth.engine.metadata;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.concurrent.NotThreadSafe;

import com.google.common.annotations.Beta;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;

import eu.eidas.auth.engine.ProtocolEngineI;

/**
 * @deprecated this code is not encapsulated at all (it exposes its mutable internal state to other classes in the same package)
 */
@NotThreadSafe
@Deprecated
@Beta
public class MetadataConfigParams {
    static final String SP_ID_PREFIX="SP";
    static final String IDP_ID_PREFIX="IDP";
    static final String DEFAULT_LANG="en";

    public static final String CONNECTOR_ORG_NAME = "connector.organization.name";
    public static final String SERVICE_ORG_NAME = "service.organization.name";
    public static final String ORG_NAME = "organization.name";

    /**
     * 24 hours in seconds
     */
    public static final long ONE_DAY_DURATION=86400;

    boolean wantAssertionsSigned=false;
    boolean authnRequestsSigned=false;
    String assertionConsumerUrl="";
    String role="";
    String entityID;
    Signature spSignature;
    Signature idpSignature;
    Credential encryptionCredential;
    Credential signingCredential;
    Credential idpEncryptionCredential;
    Credential idpSigningCredential;
    Credential spEncryptionCredential;
    Credential spSigningCredential;
    Set<String> protocolBinding=new HashSet<String>();
    HashMap<String,String> protocolBindingLocation=new HashMap<String,String>();
    //supported protocol: SAML 2
    String spSamlProtocol= SAMLConstants.SAML20P_NS;
    String idpSamlProtocol=SAMLConstants.SAML20P_NS;
    String countryName;
    String nodeUrl;
    String emailAddress;
    ProtocolEngineI idpEngine;
    ProtocolEngineI spEngine;
    String assuranceLevel;
    String spType;
    String digestMethods;
    String signingMethods;
    String encryptionAlgorithms;
    long validityDuration=ONE_DAY_DURATION;
    Contact supportContact;
    Contact technicalContact;
    String OrganizationName;

    public boolean isWantAssertionsSigned() {
        return wantAssertionsSigned;
    }

    public void setWantAssertionsSigned(boolean wantAssertionsSigned) {
        this.wantAssertionsSigned = wantAssertionsSigned;
    }

    public boolean isAuthnRequestsSigned() {
        return authnRequestsSigned;
    }

    public void setAuthnRequestsSigned(boolean authnRequestsSigned) {
        this.authnRequestsSigned = authnRequestsSigned;
    }

    public String getAssertionConsumerUrl() {
        return assertionConsumerUrl;
    }

    public void setAssertionConsumerUrl(String assertionConsumerUrl) {
        this.assertionConsumerUrl = assertionConsumerUrl;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getEntityID() {
        return entityID;
    }

    public void setEntityID(String entityID) {
        this.entityID = entityID;
    }

    public Signature getSPSignature() {
        return spSignature;
    }

    public void setSPSignature(Signature signature) {
        this.spSignature = signature;
    }

    public Signature getIDPSignature() {
        return idpSignature;
    }

    public void setIDPSignature(Signature idpSignature) {
        this.idpSignature = idpSignature;
    }

    public Credential getEncryptionCredential() {
        return encryptionCredential;
    }

    public void setEncryptionCredential(Credential encryptionCredential) {
        this.encryptionCredential = encryptionCredential;
    }

    public Credential getSigningCredential() {
        return signingCredential;
    }

    public void setSigningCredential(Credential signingCredential) {
        this.signingCredential = signingCredential;
    }

    public String getSpSamlProtocol() {
        return spSamlProtocol;
    }

    public void setSpSamlProtocol(String spSamlProtocol) {
        this.spSamlProtocol = spSamlProtocol;
    }

    public String getIdpSamlProtocol() {
        return idpSamlProtocol;
    }

    public void setIdpSamlProtocol(String idpSamlProtocol) {
        this.idpSamlProtocol = idpSamlProtocol;
    }

    public Credential getIdpEncryptionCredential() {
        return idpEncryptionCredential;
    }

    public void setIdpEncryptionCredential(Credential idpEncryptionCredential) {
        this.idpEncryptionCredential = idpEncryptionCredential;
    }

    public Credential getIdpSigningCredential() {
        return idpSigningCredential;
    }

    public void setIdpSigningCredential(Credential idpSigningCredential) {
        this.idpSigningCredential = idpSigningCredential;
    }

    public Credential getSpEncryptionCredential() {
        return spEncryptionCredential;
    }

    public void setSpEncryptionCredential(Credential spEncryptionCredential) {
        this.spEncryptionCredential = spEncryptionCredential;
    }

    public Credential getSpSigningCredential() {
        return spSigningCredential;
    }

    public void setSpSigningCredential(Credential spSigningCredential) {
        this.spSigningCredential = spSigningCredential;
    }

    public String getCountryName() {
        return countryName;
    }

    public void setCountryName(String countryName) {
        this.countryName = countryName;
    }

    public String getNodeUrl() {
        return nodeUrl;
    }

    public void setNodeUrl(String nodeUrl) {
        this.nodeUrl = nodeUrl;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }
    public ProtocolEngineI getIdpEngine() {
        return idpEngine;
    }

    public void setIdpEngine(ProtocolEngineI idpEngine) {
        this.idpEngine = idpEngine;
    }

    public ProtocolEngineI getSpEngine() {
        return spEngine;
    }

    public void setSpEngine(ProtocolEngineI spEngine) {
        this.spEngine = spEngine;
    }

    public String getAssuranceLevel() {
        return assuranceLevel;
    }

    public void setAssuranceLevel(String assuranceLevel) {
        this.assuranceLevel = assuranceLevel;
    }

    public Set<String> getProtocolBinding() {
        return this.protocolBinding;
    }

    public HashMap<String, String> getProtocolBindingLocation() {
        return protocolBindingLocation;
    }

    public String getSpType() {
        return spType;
    }

    public void setSpType(String spType) {
        this.spType = spType;
    }

    public String getDigestMethods() {
        return digestMethods;
    }

    public void setDigestMethods(String digestMethods) {
        this.digestMethods = digestMethods;
    }

    public String getSigningMethods() {
        return signingMethods;
    }

    public void setSigningMethods(String signingMethods) {
        this.signingMethods = signingMethods;
    }

    public String getEncryptionAlgorithms() {
        return encryptionAlgorithms;
    }

    public void setEncryptionAlgorithms(String encryptionAlgorithms) {
        this.encryptionAlgorithms = encryptionAlgorithms;
    }

    public long getValidityDuration() {
        return validityDuration;
    }

    public void setValidityDuration(long validityDuration) {
        if(validityDuration>0 && validityDuration<Integer.MAX_VALUE) {
            this.validityDuration = validityDuration;
        }else{
            this.validityDuration=ONE_DAY_DURATION;
        }
    }
    public Contact getSupportContact() {
        return supportContact;
    }

    public void setSupportContact(Contact supportContact) {
        this.supportContact = supportContact;
    }

    public Contact getTechnicalContact() {
        return technicalContact;
    }

    public void setTechnicalContact(Contact technicalContact) {
        this.technicalContact = technicalContact;
    }

    public String getOrganizationName() {
        return OrganizationName;
    }

    public void setOrganizationName(String organizationName) {
        OrganizationName = organizationName;
    }
}
