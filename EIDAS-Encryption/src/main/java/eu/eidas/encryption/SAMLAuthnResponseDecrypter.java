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

package eu.eidas.encryption;

import eu.eidas.encryption.exception.DecryptionException;
import eu.eidas.encryption.exception.MarshallException;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.XMLObjectHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;

import java.nio.charset.Charset;

/**
 * Created by bodabel on 01/12/2014.
 */
public final class SAMLAuthnResponseDecrypter {

    private static final Logger LOGGER = LoggerFactory.getLogger(SAMLAuthnResponseDecrypter.class.getName());
    private String jcaProviderName;

    /**
     * Intantiation using the default data and key encryption algorithm
     */
    public SAMLAuthnResponseDecrypter() {
    }

    private void performDecryption(Response samlResponseDecryptee,final BasicX509Credential credential) throws DecryptionException, MarshallException{


        try {
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("SAML Response XMLObject to decrypt: " + new String(MarshallingUtil.marshall(samlResponseDecryptee), Charset.forName("UTF-8")));
            }
            for (EncryptedAssertion encAssertion : samlResponseDecryptee.getEncryptedAssertions()) {
                EncryptedKey encryptedSymmetricKey = encAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0);

                //KEY DECRYPTER
                Decrypter keyDecrypter = new Decrypter(null, new StaticKeyInfoCredentialResolver(credential), null);
                SecretKey dataDecKey = (SecretKey) keyDecrypter.decryptKey(
                        encryptedSymmetricKey, encAssertion.getEncryptedData().getEncryptionMethod().getAlgorithm());
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("SAML Response decrypting with data encryption algorithm: '" + encAssertion.getEncryptedData().getEncryptionMethod().getAlgorithm() + "'");
                }

                //DATA DECRYPTER
                Credential dataDecCredential = SecurityHelper.getSimpleCredential(dataDecKey);
                Decrypter dataDecrypter = new Decrypter(new StaticKeyInfoCredentialResolver(dataDecCredential), null, null);
                dataDecrypter.setRootInNewDocument(true);
                if(getJcaProviderName()!=null) {
                    dataDecrypter.setJCAProviderName(getJcaProviderName());
                }
                //https://jira.spring.io/browse/SES-148
                //http://digitaliser.dk/forum/2621692
                Assertion assertion = dataDecrypter.decrypt(encAssertion);
                samlResponseDecryptee.getAssertions().add(assertion);
            }
            samlResponseDecryptee.getEncryptedAssertions().clear();

        } catch(org.opensaml.xml.encryption.DecryptionException de){
            throw new DecryptionException(de);
        }

        if (LOGGER.isTraceEnabled()) {
            byte[] samlResponseDecrypted = MarshallingUtil.marshall(samlResponseDecryptee);
            LOGGER.trace("SAML Response XMLObject decrypted: " + new String(samlResponseDecrypted, Charset.forName("UTF-8")));
        }

    }
    public Response decryptSAMLResponse(final Response samlResponseEncrypted, final BasicX509Credential credential) throws DecryptionException {
        //Make a copy of the parameter samlResponse
        Response samlResponseDecryptee = null;
        try {
            samlResponseDecryptee = XMLObjectHelper.cloneXMLObject(samlResponseEncrypted);
            SAMLResponseLogHelper.setBeforeDecryptionSAMLResponse(samlResponseDecryptee);
        } catch (MarshallingException e) {
            throw new DecryptionException(e);
        } catch (UnmarshallingException e) {
            throw new DecryptionException(e);
        }

        try{
            performDecryption(samlResponseDecryptee, credential);
        }catch (MarshallException e) {
            throw new DecryptionException(e);
        }
        SAMLResponseLogHelper.setAfterDecryptionSAMLResponse(samlResponseDecryptee);
        return samlResponseDecryptee;
    }


    public byte[] decryptSAMLResponseAndMarshall(final Response samlResponse, final BasicX509Credential credential) throws DecryptionException {

        Response samlResponseDecryptee = this.decryptSAMLResponse(samlResponse, credential);

        byte[] samlResponseDecrypted;
        try {
            samlResponseDecrypted = MarshallingUtil.marshall(samlResponseDecryptee);
        }catch (MarshallException e){
            throw new DecryptionException(e);
        }

        return samlResponseDecrypted;
    }
    public String getJcaProviderName() {
        return jcaProviderName;
    }

    public void setJcaProviderName(String jcaProviderName) {
        this.jcaProviderName = jcaProviderName;
    }

}
