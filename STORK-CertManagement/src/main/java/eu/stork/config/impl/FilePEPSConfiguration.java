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
package eu.stork.config.impl;

import eu.stork.config.PEPSConfiguration;
import eu.stork.config.impl.samlmetadata.MetadataRepositoryImpl;
import eu.stork.config.peps.PEPSCountry;
import eu.stork.config.peps.PEPSMetaconfigProvider;
import eu.stork.config.peps.PEPSParameter;
import eu.stork.config.samlmetadata.MetadataRepository;
import eu.stork.samlengineconfig.impl.CertificateManagerConfigurationImpl;

import eu.stork.samlengineconfig.impl.tools.StorkConfigManagerUtil;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 *
 */
public class FilePEPSConfiguration extends PEPSConfiguration {
    private static final Logger LOG = LoggerFactory.getLogger(FilePEPSConfiguration.class.getName());
    Properties pepsProperties;

    private static final String COUNTRY_PREFIX="cpeps";
    private static final String COUNTRY_ID_SUFFIX=".id";
    private static final String COUNTRY_NAME_SUFFIX=".name";
    private static final String COUNTRY_URL_SUFFIX=".url";
    private static final String COUNTRY_SKEW_SUFFIX=".skew";

    private final static String CPEPS_NUMBER_NAME="cpeps.number";
    private final static String SAML_ENGINE_REPOSITORY_URL="peps.engine.repo";
    @Override
    public void load() {
        parameters=new HashMap<String, PEPSParameter>();
        pepsProperties = new Properties();
        if(metadataProvider instanceof PEPSMetaconfigProviderImpl) {
            PEPSMetaconfigProviderImpl metadataProviderImpl=(PEPSMetaconfigProviderImpl)metadataProvider;
            for(PEPSConfFile f:metadataProviderImpl.getFileList()){
                Properties p=new Properties();
                if(PEPSConfFile.FileType.XML.toString().equalsIgnoreCase(f.getType())) {
                    p=((FileConfigurationRepository) repository).loadPropertiesFromXML(f.getFileName());
                }else if(PEPSConfFile.FileType.PROPERTIES.toString().equalsIgnoreCase(f.getType())) {
                    p=((FileConfigurationRepository) repository).loadPropsFromTextFile(f.getFileName());
                }
                loadParametersMap(p,f);
                for(String key:p.stringPropertyNames()){
                    pepsProperties.put(key, p.getProperty(key));
                }
            }
            loadCountries();
        }
    }

    public Properties getPepsProperties(){
        return pepsProperties;
    }
    private void loadParametersMap(Properties properties, PEPSConfFile sourceFile){
        Iterator iterator=properties.keySet().iterator();
        while(iterator.hasNext()){
            PEPSParameter p=new PEPSParameter();
            p.setName(iterator.next().toString());
            p.setValue(properties.getProperty(p.getName()));
            PEPSParameterMetaImpl metadata = (PEPSParameterMetaImpl)metadataProvider.getMetadata(p.getName());
            if(metadata==null){
                metadata = new PEPSParameterMetaImpl();
                metadata.setName(p.getName());
                metadataProvider.addMetadata(p.getName(), metadata);
            }
            metadata.setSourceFile(sourceFile);
            p.setMetadata(metadata);
            parameters.put(p.getName(), p);
        }
    }

    private void loadCountries(){
        String cpepsNumberValue=pepsProperties.getProperty(CPEPS_NUMBER_NAME);
        if(cpepsNumberValue==null || cpepsNumberValue.isEmpty()){
            LOG.info("ERROR : Incorrect number of countries in peps.xml");
        }
        int cpepsNumber = 0;
        try {
            cpepsNumber = Math.abs(Integer.parseInt(cpepsNumberValue));
        }catch (NumberFormatException nfe){
            LOG.info("ERROR : Incorrect number of countries in peps.xml {}", nfe);
        }
        countries=new ArrayList<PEPSCountry>(cpepsNumber);
        for(int i=1;i<=cpepsNumber;i++){
            String countryID=COUNTRY_PREFIX+i;
            String countryId=pepsProperties.getProperty(countryID+COUNTRY_ID_SUFFIX);
            String countryName=pepsProperties.getProperty(countryID+COUNTRY_NAME_SUFFIX);
            String countryUrl=pepsProperties.getProperty(countryID+COUNTRY_URL_SUFFIX);
            String countrySkewTime=pepsProperties.getProperty(countryID+COUNTRY_SKEW_SUFFIX);
            if(StringUtils.isBlank(countryId)){
                LOG.info("ERROR : Country in peps.xml countryId={1}, countryName={2}, url={3}, skewTime={4}", countryId, countryName, countryUrl, countrySkewTime);
                break;
            }
            PEPSCountry country=new PEPSCountry(countryId, countryName, countryUrl, countrySkewTime);
            countries.add(country);
            pepsProperties.remove(countryID + COUNTRY_ID_SUFFIX);
            pepsProperties.remove(countryID + COUNTRY_NAME_SUFFIX);
            pepsProperties.remove(countryID + COUNTRY_URL_SUFFIX);
            pepsProperties.remove(countryID + COUNTRY_SKEW_SUFFIX);
        }
        loadEncryptionConf();

    }
    private void loadEncryptionConf(){
        CertificateManagerConfigurationImpl samlConfig=null;
        Properties encryptionProps=new Properties();
        if(pepsProperties.containsKey(SAML_ENGINE_REPOSITORY_URL)){
            //in this case a SamlEngineConfiguration instance will hold the SamlEngine configuration
            samlConfig = StorkConfigManagerUtil.getInstance().getCertificateManagerConfiguration();
        }
        if(samlConfig!=null){
            encryptionProps = ((FileConfigurationRepository) repository).loadPropertiesFromXML("encryptionConf.xml");
        }
        for(PEPSCountry country:countries){
            String encryptionKey="EncryptTo."+country.getCode();
            if(encryptionProps.containsKey(encryptionKey)){
                country.setEncryptionTo(Boolean.parseBoolean(encryptionProps.getProperty(encryptionKey)));
            }
            encryptionKey="EncryptFrom."+country.getCode();
            if(encryptionProps.containsKey(encryptionKey)){
                country.setEncryptionFrom(Boolean.parseBoolean(encryptionProps.getProperty(encryptionKey)));
            }
        }
    }

    private void saveCountries(){
        //merge countries with pepsProperties
        setCountryParameter(CPEPS_NUMBER_NAME, Integer.toString(countries.size()));
        for(int i=1;countries!=null && i<=countries.size();i++){
            String countryID=COUNTRY_PREFIX+i;
            PEPSCountry currentCountry=countries.get(i-1);
            setCountryParameter(countryID + COUNTRY_ID_SUFFIX, currentCountry.getCode());
            setCountryParameter(countryID + COUNTRY_NAME_SUFFIX, currentCountry.getName());
            setCountryParameter(countryID + COUNTRY_URL_SUFFIX, currentCountry.getPepsUrl());
            setCountryParameter(countryID + COUNTRY_SKEW_SUFFIX, Integer.toString(currentCountry.getSkewTime()));
        }
    }

    private void setCountryParameter(String name, String value) {
        pepsProperties.setProperty(name, value);
        PEPSParameterMetaImpl metadata = (PEPSParameterMetaImpl) (metadataProvider.getMetadata(name));
        if (metadata == null || !parameters.containsKey(name)) {
            PEPSParameter newParameter=new PEPSParameter();
            newParameter.setName(name);
            newParameter.setValue(value);
            metadata = new PEPSParameterMetaImpl();
            metadata.setSourceFile(metadataProvider.getDefaultConfFile());
            metadata.setName(name);
            newParameter.setMetadata(metadata);
            metadataProvider.addMetadata(name, metadata);
            parameters.put(name, newParameter);
        }
        parameters.get(name).setValue(value);
    }


    @Override
    public void save() {
        CertificateManagerConfigurationImpl samlConfig=null;
        if(pepsProperties.containsKey(SAML_ENGINE_REPOSITORY_URL)){
            //in this case a SamlEngineConfiguration instance will hold the SamlEngine configuration
            samlConfig = StorkConfigManagerUtil.getInstance().getCertificateManagerConfiguration();
        }
        saveCountries();

        Properties encryptionProps=new Properties();
        for(PEPSCountry country:countries){
            encryptionProps.setProperty("EncryptTo."+country.getCode(), Boolean.toString(country.isEncryptionTo()));
            encryptionProps.setProperty("EncryptFrom."+country.getCode(), Boolean.toString(country.isEncryptionFrom()));
        }
        if(samlConfig!=null){
            StorkConfigManagerUtil.getInstance().saveProps("encryptionConf.xml", encryptionProps);
        }
        saveToFiles(splitParametersPerFile());
    }

    private Map<PEPSConfFile, Properties> splitParametersPerFile(){
        Map<PEPSConfFile, Properties> fileContents=new HashMap<PEPSConfFile, Properties>();
        PEPSMetaconfigProvider metadataProvider = getMetadataProvider();
        for(PEPSParameter p:parameters.values()){
            pepsProperties.setProperty(p.getName(), p.getValue());
            PEPSParameterMetaImpl metadata = (PEPSParameterMetaImpl)(metadataProvider.getMetadata(p.getName()));
            if(metadata!=null && metadata.getSourceFile()!=null){
                Properties props=fileContents.get(metadata.getSourceFile());
                if(props==null){
                    props=new Properties();
                    fileContents.put(metadata.getSourceFile(), props);
                }
                props.setProperty(p.getName(), p.getValue());
            }
        }
        return fileContents;
    }
    private void saveToFiles(Map<PEPSConfFile, Properties> fileContents){
        for(Map.Entry<PEPSConfFile, Properties> entry:fileContents.entrySet()){
            if(PEPSConfFile.FileType.XML.toString().equalsIgnoreCase(entry.getKey().getType())){
                ((FileConfigurationRepository) repository).savePropertiesToXML(entry.getKey().getFileName(), entry.getValue());
            }else if(PEPSConfFile.FileType.PROPERTIES.toString().equalsIgnoreCase(entry.getKey().getType())) {
                ((FileConfigurationRepository) repository).savePropertiesToTextFile(entry.getKey().getFileName(), entry.getValue());
            }
        }

    }

    @Override
    public MetadataRepository getSamlMetadataRepository() {
        MetadataRepositoryImpl samlMetadataRepository=(MetadataRepositoryImpl)super.getSamlMetadataRepository();
        if(pepsProperties==null){
            load();
        }
        if(samlMetadataRepository.getFileService().getRepositoryDir()==null) {
            samlMetadataRepository.getFileService().setRepositoryDir(pepsProperties.getProperty(MetadataRepositoryImpl.PEPS_SAML_METADATA_LOCATION));
        }
        return samlMetadataRepository;
    }

}
