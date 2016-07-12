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
package eu.stork.samlengineconfig.impl.tools;

import eu.stork.impl.file.FileService;
import eu.stork.samlengineconfig.impl.CertificateManagerConfigurationImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import java.util.Properties;

public class StorkConfigManagerUtil implements ApplicationContextAware {
    private static final Logger LOG = LoggerFactory.getLogger(StorkConfigManagerUtil.class.getName());
    static StorkConfigManagerUtil activeInstance=null;
    static String samlEngineSubDirectory=null;
    FileService fileService=null;
    CertificateManagerConfigurationImpl certificateManagerConfiguration=null;

    public static StorkConfigManagerUtil getInstance(){
        if(activeInstance==null){
            LOG.error("ERROR : using StorkConfigManagerUtil before init");
        }
        return activeInstance;
    }
    public void setApplicationContext(ApplicationContext ctx) throws BeansException {
        StorkConfigManagerUtil.setActiveInstance(ctx.getBean(StorkConfigManagerUtil.class));
        setCertificateManagerConfiguration(ctx.getBean(CertificateManagerConfigurationImpl.class));
        if(certificateManagerConfiguration.getParentConfiguration()!=null) {
            StorkConfigManagerUtil.setDirectory(certificateManagerConfiguration.getLocation());
        }else{
            StorkConfigManagerUtil.setDirectory(null);
        }
    }

    private static void setDirectory(String location){
        samlEngineSubDirectory = location;
    }
    private static void setActiveInstance(StorkConfigManagerUtil instance){
        activeInstance = instance;
    }


    public FileService getFileService() {
        return fileService;
    }

    public void setFileService(FileService fileService) {
        this.fileService = fileService;
    }

    private String getActualFileName(String fileName){
        return samlEngineSubDirectory==null?fileName:samlEngineSubDirectory+"/"+fileName;
    }
    public boolean existsFile(String fileName){
        return fileService.existsFile(getActualFileName(fileName));
    }
    public Properties loadProps(String fileName){
        return fileService.loadPropsFromXml(getActualFileName(fileName));
    }
    public void saveProps(String fileName, Properties props){
        fileService.saveToXMLFile(getActualFileName(fileName), props);
    }
    public void saveFile(String fileName, String fileContents){
        if(fileService==null || !fileService.existsFile("")){
            LOG.error("ERROR : the persistence support is not active");
            return ;
        }
        //String contents= serializeEngineInstance(config);
        fileService.stringToFile(getActualFileName(fileName), fileContents);

    }
    public String loadFileAsString(String fileName) {
        if (fileService == null || !fileService.existsFile("")) {
            LOG.error("ERROR : the file service is incorrectly configured");
            return "";
        }
        return fileService.fileToString(getActualFileName(fileName));
    }

    public byte[] loadBinaryFile(String fileName) {
        if (fileService == null || !fileService.existsFile("")) {
            LOG.error("ERROR : the file service is incorrectly configured");
            return new byte[0];
        }
        return fileService.loadBinaryFile(getActualFileName(fileName));
    }

    public CertificateManagerConfigurationImpl getCertificateManagerConfiguration() {
        return certificateManagerConfiguration;
    }

    public void setCertificateManagerConfiguration(CertificateManagerConfigurationImpl certificateManagerConfiguration) {
        this.certificateManagerConfiguration = certificateManagerConfiguration;
    }
}
