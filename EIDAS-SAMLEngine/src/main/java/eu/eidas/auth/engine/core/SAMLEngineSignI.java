/* 
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 * 
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * Licence for the specific language governing permissions and limitations under
 * the Licence.
 */

package eu.eidas.auth.engine.core;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Properties;

import eu.eidas.auth.engine.metadata.MetadataProcessorI;
import eu.eidas.engine.exceptions.SAMLEngineException;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;

/**
 * The Interface SAMLEngineSignI.
 * 
 */
public interface SAMLEngineSignI extends SAMLEngineModuleI {
    String SIGNATURE_ALGORITHM="signature.algorithm";
    String SIGNATURE_ALGORITHMS_WHITELIST="signature.algorithm.whitelist";
    enum SignAlgoritm{
        SHA_512,
        SHA_384,
        SHA_256
    };

    /**
     * Sign.
     * 
     * @param tokenSaml the token SAML
     * 
     * @return the sAML object
     * 
     * @throws SAMLEngineException the SAML engine exception
     */
    SAMLObject sign(SignableSAMLObject tokenSaml) throws SAMLEngineException;

    /**
     * Sign metadata.
     *
     * @param tokenSaml the token SAML
     *
     * @return the sAML object
     *
     * @throws SAMLEngineException the SAML engine exception
     */
    SAMLObject signMetadata(SignableSAMLObject tokenSaml) throws SAMLEngineException;

    /**
     * Gets the certificate.
     * 
     * @return the certificate
     */
    X509Certificate getCertificate();

    /**
     * Gets the trustStore used when validating SAMLTokens
     * 
     * @return the trustStore
     *   
     */
	KeyStore getTrustStore();
	
    /**
     * Validate signature.
     *
     * @param tokenSaml the token SAML
     * @param messageFormat the message format used by the saml object
     *
     * @return the sAML object
     * 
     * @throws SAMLEngineException the SAML engine exception
     */
    SAMLObject validateSignature(SignableSAMLObject tokenSaml, String messageFormat)
	    throws SAMLEngineException;

    /**
     * Initialize the signature module.
     * 
     * @param fileConf the configuration file.
     * 
     * @throws SAMLEngineException the EIDASSAML engine runtime
     *             exception
     */
    void init(String fileConf) throws SAMLEngineException;
    void init(Properties props) throws SAMLEngineException;
    void setProperty(String propName, String propValue);

    /**
     * Load cryptographic service provider.
     * 
     * @throws SAMLEngineException the SAML engine exception
     */
    void loadCryptServiceProvider() throws SAMLEngineException;

    /**
     *
     * @param keystore the keystore used for getting the certificate to sign
     * @return the signature used by signer to sign
     */
    Signature computeSignature(KeyStore keystore)throws SAMLEngineException;

    /**
     *
     * @param keystore the keystore used for getting the certificate to sign
     * @param target - the target (for which type of object the signature will be used)
     * @return the credential used by signer to sign
     */
    Credential getSigningCredential(KeyStore keystore, String target) throws SAMLEngineException;
    /**
     *
     * @param keystore the keystore used for getting the certificate to sign
     * @return the credential used to check the signature
     */
    Credential getPublicSigningCredential(KeyStore keystore) throws SAMLEngineException;

    void setMetadataProcessor(MetadataProcessorI procesor);

}
