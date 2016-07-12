/*
 * Copyright (c) 2015 by European Commission
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

package eu.stork.encryption;

import eu.stork.encryption.exception.EncryptionException;
import eu.stork.encryption.exception.MarshallException;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.XMLObjectHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;

/**
 * Created by bodabel on 01/12/2014.
 */
public final class SAMLAuthnResponseEncrypter {

    private static final Logger LOGGER = LoggerFactory
            .getLogger(SAMLAuthnResponseEncrypter.class.getName());

    private String dataEncAlgorithm;

    private String keyEncAlgorithm;
    private String jcaProviderName;

    /**
     * Intantiation using the default data and key encryption algorithm
     */
    public SAMLAuthnResponseEncrypter() {
    }

    /**
     * Intantiation specifying data and key encryption algorithm
     */
    public SAMLAuthnResponseEncrypter(String dataEncAlgorithm, String keyEncAlgorithm) {
        this.dataEncAlgorithm = dataEncAlgorithm;
        this.keyEncAlgorithm = keyEncAlgorithm;
    }

    String getDataEncAlgorithm() {
        if (dataEncAlgorithm == null) {
            dataEncAlgorithm = ISAMLAuthnResponseEncryptionConstants.DEFAULT_DATA_ENCRYPTION_ALGORITHM;
        }
        return dataEncAlgorithm;
    }

    public void setDataEncAlgorithm(String dataEncAlgorithm) {
        this.dataEncAlgorithm = dataEncAlgorithm;
    }

    String getKeyEncAlgorithm() {
        if (keyEncAlgorithm == null) {
            keyEncAlgorithm= ISAMLAuthnResponseEncryptionConstants.DEFAULT_KEY_ENCRYPTION_ALGORITHM;
        }
        return keyEncAlgorithm;
    }

    public void setKeyEncAlgorithm(String keyEncAlgorithm) {
        this.keyEncAlgorithm = keyEncAlgorithm;
    }

    private Response cloneResponse(final Response samlResponse)throws EncryptionException{
        Response samlResponseEncryptee;
        try {
            samlResponseEncryptee = XMLObjectHelper.cloneXMLObject(samlResponse);
        } catch (MarshallingException e) {
            throw new EncryptionException(e);
        } catch (UnmarshallingException e) {
            throw new EncryptionException(e);
        } catch (Exception e) {
            throw new EncryptionException(e);
        }
        return samlResponseEncryptee;
    }
    private void performEncryption(Response samlResponseEncryptee, final Credential credential) throws EncryptionException {
        try {
            // Set Data Encryption parameters
            EncryptionParameters encParams = new EncryptionParameters();
            encParams.setAlgorithm(this.getDataEncAlgorithm());
            // Set Key Encryption parameters
            KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
            kekParams.setEncryptionCredential(credential);
            kekParams.setAlgorithm(this.getKeyEncAlgorithm());
            KeyInfoGeneratorFactory kigf =
                    Configuration.getGlobalSecurityConfiguration()
                            .getKeyInfoGeneratorManager().getDefaultManager()
                            .getFactory(credential);
            kekParams.setKeyInfoGenerator(kigf.newInstance());
            // Setup Open SAML Encrypter
            org.opensaml.saml2.encryption.Encrypter samlEncrypter = new org.opensaml.saml2.encryption.Encrypter(encParams, kekParams);
            samlEncrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);
            if(getJcaProviderName()!=null) {
                samlEncrypter.setJCAProviderName(getJcaProviderName());
            }

            for (Assertion assertion : samlResponseEncryptee.getAssertions()) {
                manageNamespaces(assertion);
            }
            SAMLResponseLogHelper.setBeforeEncryptionSAMLResponse(samlResponseEncryptee);
            for (Assertion assertion : samlResponseEncryptee.getAssertions()) {
                EncryptedAssertion encryptedAssertion = samlEncrypter.encrypt(assertion);
                samlResponseEncryptee.getEncryptedAssertions().add(encryptedAssertion);
            }
            samlResponseEncryptee.getAssertions().clear();


        } catch (Exception e) {
            throw new EncryptionException(e);
        }

    }

    public Response encryptSAMLResponse(final Response samlResponse, final Credential credential) throws EncryptionException {
        //Make a copy of the parameter samlResponse
        Response samlResponseEncryptee=cloneResponse(samlResponse);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("SAML Response encrypting with data encryption algorithm: '" + this.getDataEncAlgorithm() + "'");
            LOGGER.debug("SAML Response encrypting with key encryption algorithm: '" + this.getKeyEncAlgorithm() + "'");
        }
        try {
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("SAML Response XMLObject to encrypt: " + new String(MarshallingUtil.marshall(samlResponse), Charset.forName("UTF-8")));
            }
            performEncryption(samlResponseEncryptee, credential);

            if (LOGGER.isTraceEnabled()) {
                byte[] samlResponseEncrypted = MarshallingUtil.marshall(samlResponseEncryptee);
                LOGGER.trace("SAML Response XMLObject encrypted: " + new String(samlResponseEncrypted, Charset.forName("UTF-8")));
            }
        }catch (MarshallException e){
            throw new EncryptionException(e);
        }

        SAMLResponseLogHelper.setAfterEncryptionSAMLResponse(samlResponseEncryptee);
        return samlResponseEncryptee;
    }

    /**
     * Manage specific namespace (e.g.saml2:)
     * @param assertion
     */
    private void manageNamespaces(Assertion assertion) {
        if (assertion.getDOM().getAttributeNode("xmlns:saml2") == null) {
            Namespace saml2NS = new Namespace("urn:oasis:names:tc:SAML:2.0:assertion","saml2");
            assertion.getNamespaceManager().registerNamespaceDeclaration(saml2NS);
            assertion.getDOM().setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:saml2","urn:oasis:names:tc:SAML:2.0:assertion");
        }
        if (assertion.getDOM().getAttributeNode("xmlns:stork") == null) {
            Namespace storkNS = new Namespace("urn:eu:stork:names:tc:STORK:1.0:assertion","stork");
            assertion.getNamespaceManager().registerNamespaceDeclaration(storkNS);
            assertion.getDOM().setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:stork","urn:eu:stork:names:tc:STORK:1.0:assertion");
        }
    }

    public byte[] encryptSAMLResponseAndMarshall(final Response samlResponse, final BasicX509Credential credential) throws EncryptionException {

        Response samlResponseEncryptee = this.encryptSAMLResponse(samlResponse, credential);
        byte[] samlResponseEncrypted;
        try {
            samlResponseEncrypted = MarshallingUtil.marshall(samlResponseEncryptee);
        }catch(MarshallException e){
            throw new EncryptionException(e);
        }

        return samlResponseEncrypted;
    }

    public String getJcaProviderName() {
        return jcaProviderName;
    }

    public void setJcaProviderName(String jcaProviderName) {
        this.jcaProviderName = jcaProviderName;
    }
}
