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
package eu.stork.config.impl.marshaller;

import eu.stork.config.impl.*;
import eu.stork.impl.file.FileService;
import eu.stork.samlengineconfig.impl.tools.StorkConfigManagerUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import java.io.StringReader;

/**
 * serialize/deserialize a PEPSMetadata configuration
 */
public class PEPSMetadataUnmarshallerImpl {
    private static final Class JAXB_CLASSES[]={PEPSMetaconfigHolderImpl.class, CategoryListImpl.class, CategoryImpl.class,
            PEPSMetaconfigListImpl.class, PEPSParameterMetaImpl.class, PEPSConfFile.class, FileListImpl.class};
    private static final Logger LOG = LoggerFactory.getLogger(PEPSMetadataUnmarshallerImpl.class.getName());
    private FileService fileService;
    private String directory;
    public PEPSMetaconfigHolderImpl readPEPSMetadataFromString(String config) {
        StringReader reader = new StringReader(config);
        Object unmarshallResult = null;
        try {
            JAXBContext context = JAXBContext.newInstance(JAXB_CLASSES);
            Unmarshaller um = context.createUnmarshaller();
            unmarshallResult = um.unmarshal(reader);
        } catch (Exception exc) {
            LOG.error("ERROR : error reading peps metadata " + exc.getMessage());
            LOG.debug("ERROR : error reading peps metadata " + exc);
        }

        if (unmarshallResult instanceof PEPSMetaconfigHolderImpl){
            PEPSMetaconfigHolderImpl holder = (PEPSMetaconfigHolderImpl) unmarshallResult;
            return holder;
        }else{
            LOG.error("ERROR : unmarshalling result is not an PEPSMetadataHolder object");
            return null;
        }
    }
    public PEPSMetaconfigHolderImpl readPEPSMetadataFromFile( String fileName ){
        if(!StorkConfigManagerUtil.getInstance().existsFile(fileName)){
            return null;
        }
        return readPEPSMetadataFromString(StorkConfigManagerUtil.getInstance().loadFileAsString(fileName));
    }

    public FileService getFileService() {
        return fileService;
    }

    public void setFileService(FileService fileService) {
        this.fileService = fileService;
    }

    public String getDirectory() {
        return directory;
    }

    public void setDirectory(String directory) {
        this.directory = directory;
    }
}
