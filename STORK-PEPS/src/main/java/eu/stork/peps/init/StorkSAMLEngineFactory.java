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

package eu.stork.peps.init;

import eu.stork.peps.auth.commons.PEPSErrors;
import eu.stork.peps.auth.commons.PEPSUtil;
import eu.stork.peps.auth.commons.PEPSValues;
import eu.stork.peps.auth.commons.exceptions.InternalErrorPEPSException;
import eu.stork.peps.auth.engine.core.SAMLEngineEncryptionI;
import eu.stork.peps.auth.engine.metadata.MetadataProcessorI;
import eu.stork.peps.exceptions.STORKSAMLEngineException;
import eu.stork.peps.utils.PEPSErrorUtil;
import eu.stork.peps.utils.PropertiesUtil;
import eu.stork.samlengineconfig.CertificateConfigurationManager;
import eu.stork.peps.auth.engine.STORKSAMLEngine;
import eu.stork.peps.auth.engine.core.SAMLEngineSignI;
import eu.stork.peps.auth.engine.core.StorkSAMLEngineFactoryI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * provides configured SamlEngine instances to SPEPS or CPEPS code
 */
public class StorkSAMLEngineFactory implements StorkSAMLEngineFactoryI {
    private static final Logger LOG = LoggerFactory.getLogger(StorkSAMLEngineFactory.class.getName());
    private static final Set<STORKSAMLEngine> createdEngines= Collections.newSetFromMap(new ConcurrentHashMap<STORKSAMLEngine, Boolean>());

    private CertificateConfigurationManager engineConfigurationProvider;
    private MetadataProcessorI pepsMetadataProcessor;
    /**
     * counts the number of active SAMLEngines
     */
    private  static final AtomicInteger instancesCount = new AtomicInteger();
    public StorkSAMLEngineFactory(){
    }
    public final STORKSAMLEngine getEngine(String name, Properties props) {
        STORKSAMLEngine engine=null;
        try {
            engine = STORKSAMLEngine.createSTORKSAMLEngine(name, getSafeEngineProvider());
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
                engine.setSignerProperty(PEPSValues.PEPS_METADATA_CHECK_SIGNATURE.toString(), props.getProperty(PEPSValues.PEPS_METADATA_CHECK_SIGNATURE.toString()));
                engine.setEncrypterProperty(SAMLEngineEncryptionI.DATA_ENCRYPTION_ALGORITHM, props.getProperty(SAMLEngineEncryptionI.DATA_ENCRYPTION_ALGORITHM));
                engine.setEncrypterProperty(SAMLEngineEncryptionI.ENCRYPTION_ALGORITHM_WHITELIST, props.getProperty(SAMLEngineEncryptionI.ENCRYPTION_ALGORITHM_WHITELIST));
                engine.setMandatoryResponseEncryption(props.getProperty(PEPSValues.RESPONSE_ENCRYPTION_MANDATORY.toString()));
                if(PropertiesUtil.isMetadataEnabled()) {
                    engine.setMetadataProcessor(pepsMetadataProcessor);
                }
            }
        }catch (STORKSAMLEngineException e){
            Exception exc = PEPSErrorUtil.getBaseSamlException(e);
            PEPSErrorUtil.processSAMLEngineException(exc, LOG, PEPSErrors.SAML_ENGINE_CONFIGURATION_ERROR);
        }
        if (engine == null) {
            throw new InternalErrorPEPSException(
                    PEPSUtil.getConfig(PEPSErrors.SAML_ENGINE_CONFIGURATION_ERROR
                            .errorCode()),
                    PEPSUtil.getConfig(PEPSErrors.SAML_ENGINE_CONFIGURATION_ERROR
                            .errorMessage()));
        }
        return engine;
    }
    public void releaseEngine(STORKSAMLEngine engine){
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

    public MetadataProcessorI getPepsMetadataProcessor() {
        return pepsMetadataProcessor;
    }

    public void setPepsMetadataProcessor(MetadataProcessorI pepsMetadataProcessor) {
        this.pepsMetadataProcessor = pepsMetadataProcessor;
    }
}
