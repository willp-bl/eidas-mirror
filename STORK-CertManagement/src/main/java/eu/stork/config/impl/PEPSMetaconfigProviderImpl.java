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

import eu.stork.config.impl.marshaller.PEPSMetadataUnmarshallerImpl;
import eu.stork.config.peps.PEPSMetaconfigProvider;
import eu.stork.config.peps.PEPSParameterCategory;
import eu.stork.config.peps.PEPSParameterMeta;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 *
 */
public class PEPSMetaconfigProviderImpl extends PEPSMetaconfigProvider {
    private static final Logger LOG = LoggerFactory.getLogger(PEPSMetaconfigProviderImpl.class.getName());
    private static final String DEFAULT_PEPS_CONF_FILENAME="peps.xml";
    private PEPSConfFile defaulPepsConfFile=null;

    @Override
    public Map<String, List<PEPSParameterMeta>> getCategorizedParameters() {
        if(getCategories().isEmpty()) {
            loadData();
        }

        return super.getCategorizedParameters();
    }

    @Override
    public List<PEPSParameterCategory> getCategories() {
        if(super.getCategories().isEmpty()) {
            loadData();
        }

        return super.getCategories();
    }

    private void loadData(){
        //load the info from the resurce stream
        PEPSMetaconfigHolderImpl holder = loadHolder();
        if (holder !=null && holder.getCategoryList() != null) {
            super.getCategories().clear();
            for (PEPSParameterCategory c : holder.getCategoryList().getCategories()) {
                super.getCategories().add(c);
            }
        }
        if (holder !=null && holder.getFileList() != null) {
            fillFileList(holder);
        }

        if (holder !=null && holder.getPEPSMetadataList() != null) {
            for (PEPSParameterMeta m : holder.getPEPSMetadataList().getPEPSParameterMetadaList()) {
                super.addMetadata(m.getName(), m);
            }
        }

    }
    private void fillFileList(PEPSMetaconfigHolderImpl holder){
        fileList.clear();
        for (PEPSConfFile f : holder.getFileList().getFiles()) {
            if(DEFAULT_PEPS_CONF_FILENAME.equalsIgnoreCase(f.getFileName())){
                defaulPepsConfFile=f;
            }
            fileList.add(f);
        }

    }
    private PEPSMetaconfigHolderImpl loadHolder(){
        PEPSMetaconfigHolderImpl holder = null;
        InputStream is = null;
        try{
            is = PEPSMetaconfigProviderImpl.class.getResourceAsStream("/pepsmetadata.xml");
            byte data[]=new byte[is.available()];
            is.read(data);
            holder = (new PEPSMetadataUnmarshallerImpl()).readPEPSMetadataFromString(new String(data, Charset.forName("UTF-8")));
        }catch(IOException ioe){
            LOG.error("error loading PEPS parameter metadata", ioe.getMessage());
            LOG.debug("error loading PEPS parameter metadata", ioe);
        }finally{
            if(is!=null){
                try {
                    is.close();
                }catch(IOException ioe){
                    LOG.error("error loading PEPS parameter metadata", ioe.getMessage());
                    LOG.debug("error loading PEPS parameter metadata", ioe);
                }
            }
        }
        return holder;
    }

    private List<PEPSConfFile> fileList=new ArrayList<PEPSConfFile>();

    public List<PEPSConfFile> getFileList() {
        if(fileList.isEmpty()) {
            loadData();
        }
        return fileList;
    }

    public void setFileList(List<PEPSConfFile> fileList) {
        this.fileList = fileList;
    }

    @Override
    public PEPSConfFile getDefaultConfFile(){
        return defaulPepsConfFile;
    }
}
