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
package eu.stork.config;

import eu.stork.config.peps.PEPSCountry;
import eu.stork.config.peps.PEPSMetaconfigProvider;
import eu.stork.config.peps.PEPSParameter;
import eu.stork.config.samlmetadata.MetadataRepository;
import eu.stork.samlengineconfig.SamlEngineConfiguration;

import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * PEPS.xml mapper
 */
public abstract class PEPSConfiguration {
    protected List<PEPSCountry> countries;
    protected Map<String, PEPSParameter> parameters;
    protected ConfigurationRepository repository;
    protected SamlEngineConfiguration samlEngineConfiguration;
    protected PEPSMetaconfigProvider metadataProvider;
    protected MetadataRepository samlMetadataRepository;
    public abstract void load();
    public abstract void save();

    /**
     *
     * @return name-value pairs
     */
    public abstract Properties getPepsProperties();
    public Map<String, PEPSParameter> getPepsParameters(){
        return parameters;
    }
    public List<PEPSCountry> getPepsCountries(){
        return countries;
    }


    public ConfigurationRepository getRepository() {
        return repository;
    }

    public void setRepository(ConfigurationRepository repository) {
        this.repository = repository;
    }

    public SamlEngineConfiguration getSamlEngineConfiguration() {
        return samlEngineConfiguration;
    }

    public void setSamlEngineConfiguration(SamlEngineConfiguration samlEngineConfiguration) {
        this.samlEngineConfiguration = samlEngineConfiguration;
    }

    public PEPSMetaconfigProvider getMetadataProvider() {
        return metadataProvider;
    }

    public void setMetaconfigProvider(PEPSMetaconfigProvider metadataProvider) {
        this.metadataProvider = metadataProvider;
    }

    public MetadataRepository getSamlMetadataRepository() {
        return samlMetadataRepository;
    }

    public void setSamlMetadataRepository(MetadataRepository samlMetadataRepository) {
        this.samlMetadataRepository = samlMetadataRepository;
    }
}
