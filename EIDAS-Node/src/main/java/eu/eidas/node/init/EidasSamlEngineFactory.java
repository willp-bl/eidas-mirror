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

package eu.eidas.node.init;

import eu.eidas.auth.commons.EIDASErrors;
import eu.eidas.auth.commons.EIDASUtil;
import eu.eidas.auth.commons.EIDASValues;
import eu.eidas.auth.commons.exceptions.InternalErrorEIDASException;
import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.core.SAMLEngineEncryptionI;
import eu.eidas.auth.engine.core.SAMLEngineSignI;
import eu.eidas.auth.engine.core.EidasSAMLEngineFactoryI;
import eu.eidas.auth.engine.metadata.MetadataProcessorI;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import eu.eidas.node.utils.EidasNodeErrorUtil;
import eu.eidas.node.utils.PropertiesUtil;
import eu.eidas.samlengineconfig.CertificateConfigurationManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * provides configured SamlEngine instances to Connector or ProxyService/SpecificNode code
 */
public class EidasSamlEngineFactory implements EidasSAMLEngineFactoryI {
    private static final Logger LOG = LoggerFactory.getLogger(EidasSamlEngineFactory.class.getName());
    private static final Set<EIDASSAMLEngine> createdEngines= Collections.newSetFromMap(new ConcurrentHashMap<EIDASSAMLEngine, Boolean>());

    private CertificateConfigurationManager engineConfigurationProvider;
    private MetadataProcessorI nodeMetadataProcessor;
    /**
     * counts the number of active SAMLEngines
     */
    private static final AtomicInteger instancesCount = new AtomicInteger();
    public EidasSamlEngineFactory(){
    }
    public final EIDASSAMLEngine getEngine(String name, Properties props) {
        EIDASSAMLEngine engine=null;
        try {
            engine = EIDASSAMLEngine.createSAMLEngine(name, getSafeEngineProvider());
            if (!createdEngines.contains(engine)) {
                instancesCount.incrementAndGet();
                createdEngines.add(engine);
            }
            if (props != null && engine != null) {
                engine.setSignerProperty(SAMLEngineSignI.CHECK_VALIDITY_PERIOD_PROPERTY, props.getProperty(SAMLEngineSignI.CHECK_VALIDITY_PERIOD_PROPERTY));
                engine.setSignerProperty(SAMLEngineSignI.SELF_SIGNED_PROPERTY, props.getProperty(SAMLEngineSignI.SELF_SIGNED_PROPERTY));
                engine.setSignerProperty(SAMLEngineSignI.SIGNATURE_ALGORITHM, props.getProperty(SAMLEngineSignI.SIGNATURE_ALGORITHM));
                engine.setDigestMethodAlgorithm(props.getProperty(SAMLEngineSignI.SIGNATURE_ALGORITHM));
                engine.setSignerProperty(SAMLEngineSignI.SIGNATURE_ALGORITHMS_WHITELIST, props.getProperty(SAMLEngineSignI.SIGNATURE_ALGORITHMS_WHITELIST));
                engine.setSignerProperty(EIDASValues.METADATA_CHECK_SIGNATURE.toString(), props.getProperty(EIDASValues.METADATA_CHECK_SIGNATURE.toString()));
                engine.setEncrypterProperty(SAMLEngineEncryptionI.DATA_ENCRYPTION_ALGORITHM, props.getProperty(SAMLEngineEncryptionI.DATA_ENCRYPTION_ALGORITHM));
                engine.setEncrypterProperty(SAMLEngineEncryptionI.ENCRYPTION_ALGORITHM_WHITELIST, props.getProperty(SAMLEngineEncryptionI.ENCRYPTION_ALGORITHM_WHITELIST));
                engine.setEncrypterProperty(SAMLEngineEncryptionI.CHECK_VALIDITY_PERIOD_PROPERTY, props.getProperty(SAMLEngineEncryptionI.CHECK_VALIDITY_PERIOD_PROPERTY));
                engine.setEncrypterProperty(SAMLEngineEncryptionI.SELF_SIGNED_PROPERTY, props.getProperty(SAMLEngineEncryptionI.SELF_SIGNED_PROPERTY));
                engine.setMandatoryResponseEncryption(props.getProperty(EIDASValues.RESPONSE_ENCRYPTION_MANDATORY.toString()));
                if(PropertiesUtil.isMetadataEnabled()) {
                    engine.setMetadataProcessor(nodeMetadataProcessor);
                }
            }
        }catch (EIDASSAMLEngineException e){
            Exception exc = EidasNodeErrorUtil.getBaseSamlException(e);
            EidasNodeErrorUtil.processSAMLEngineException(exc, LOG, EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR);
        }
        if (engine == null) {
            throw new InternalErrorEIDASException(
                    EIDASUtil.getConfig(EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR
                            .errorCode()),
                    EIDASUtil.getConfig(EIDASErrors.SAML_ENGINE_CONFIGURATION_ERROR
                            .errorMessage()));
        }
        return engine;
    }
    public void releaseEngine(EIDASSAMLEngine engine){
        if(engine!=null && createdEngines.contains(engine)) {
            instancesCount.decrementAndGet();
            createdEngines.remove(engine);
        }
    }
    private CertificateConfigurationManager getSafeEngineProvider(){
        if(engineConfigurationProvider != null && engineConfigurationProvider.isActive() && engineConfigurationProvider.getConfiguration() != null && !engineConfigurationProvider.getConfiguration().isEmpty()){
            return engineConfigurationProvider;
        }
        return null;
    }
    /**
     * current implementation provides only the total number of active instances
     * @param name
     * @return
     */
    public int getActiveEngineCount(String name){
        return instancesCount.get();
    }

    public CertificateConfigurationManager getEngineConfigurationProvider() {
        return engineConfigurationProvider;
    }

    public void setEngineConfigurationProvider(CertificateConfigurationManager engineConfigurationProvider) {
        this.engineConfigurationProvider = engineConfigurationProvider;
    }

    public MetadataProcessorI getNodeMetadataProcessor() {
        return nodeMetadataProcessor;
    }

    public void setNodeMetadataProcessor(MetadataProcessorI nodeMetadataProcessor) {
        this.nodeMetadataProcessor = nodeMetadataProcessor;
    }
}
