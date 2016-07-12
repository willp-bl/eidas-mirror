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
package eu.stork.samlengineconfig.impl.marshaller;

import eu.stork.impl.file.FileService;
import eu.stork.samlengineconfig.SamlEngineConfiguration;

import eu.stork.samlengineconfig.impl.*;
import eu.stork.samlengineconfig.impl.tools.StorkConfigManagerUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import java.io.StringWriter;
import java.util.Properties;

/**
 * serialize/deserialize an EngineInstance
 */
public class EngineInstanceMarshallerImpl {
    private static final Class JAXB_CLASSES[]={JAXBConfigurationParameter.class, SamlEngineConfigurationImpl.class, EngineInstanceImpl.class, InstanceConfigurationImpl.class, Properties.class};
    private static final Logger LOG = LoggerFactory.getLogger(EngineInstanceMarshallerImpl.class.getName());
    private FileService fileService;
    public String serializeEngineInstance(SamlEngineConfiguration config ){
        StringWriter writer = new StringWriter();
        if(config instanceof SamlEngineConfigurationImpl){
            SamlEngineConfigurationImpl impl=(SamlEngineConfigurationImpl)config;
            try {
                JAXBContext context = JAXBContext.newInstance(JAXB_CLASSES);
                Marshaller marshaller = context.createMarshaller();
                marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
                marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
                marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
                marshaller.marshal(impl, writer);
            }catch(Exception exc){
                LOG.error("ERROR : error saving engine instance "+exc);
            }

        }
        return writer.toString();
    }

    public void writeEngineInstanceToFile( String fileName,SamlEngineConfiguration config  ){
        String contents= serializeEngineInstance(config);
        StorkConfigManagerUtil.getInstance().saveFile(fileName, contents);
    }


    public FileService getFileService() {
        return fileService;
    }

    public void setFileService(FileService fileService) {
        this.fileService = fileService;
    }
}
