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


/**
 * umbrella for different sources of PEPS configuration parameters
 */
public class PEPSMasterConfiguration {
//    enum TYPES{
//        PEPS,
//        SAMLENGINE,
//        ENCRYPTION_CONFIG,
//    }
    ConfigurationRepository repository;
    PEPSConfiguration pepsConfiguration;

    public ConfigurationRepository getRepository() {
        return repository;
    }

    public void setRepository(ConfigurationRepository repository) {
        this.repository = repository;
    }

    public PEPSConfiguration getPepsConfiguration() {
        if(pepsConfiguration!=null && pepsConfiguration.getRepository()==null){
            pepsConfiguration.setRepository(repository);
        }
        return pepsConfiguration;
    }

    public void setPepsConfiguration(PEPSConfiguration pepsConfiguration) {
        this.pepsConfiguration = pepsConfiguration;
    }

    public byte[] getRawContent(String url){
        return getRepository().getRawContent(url);
    }
    public void setRawContent(String url, byte[] os){
        getRepository().setRawContent(url, os);
    }
    public void backup() throws ConfigurationException {
        getRepository().backup();
    }
}
