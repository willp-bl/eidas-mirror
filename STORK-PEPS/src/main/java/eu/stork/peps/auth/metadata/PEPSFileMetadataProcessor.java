/*
 * This work is Open Source and licensed by the European Commission under the
 * conditions of the European Public License v1.1
 *
 * (http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1);
 *
 * any use of this file implies acceptance of the conditions of this license.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package eu.stork.peps.auth.metadata;

import eu.stork.impl.file.FileService;
import eu.stork.peps.auth.engine.metadata.MetadataGenerator;
import org.apache.commons.io.monitor.FileAlterationListener;
import org.apache.commons.io.monitor.FileAlterationMonitor;
import org.apache.commons.io.monitor.FileAlterationObserver;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.ContextStoppedEvent;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * implements metadata cache
 * the source metadata: all readable xml files found in a configured directory
 */
public class PEPSFileMetadataProcessor implements ApplicationListener{
    private String repositoryPath;
    private FileService fileService = new FileService();
    MetadataGenerator metadataTool=new MetadataGenerator();
    /**
     * monitor the folder for changes on the files
     */
    FileAlterationMonitor monitor;
    FileAlterationObserver observer;
    XMLObserver xmlObserver;
    private static final long MONITOR_INTERVAL=1000L;
    private static final Logger LOG = LoggerFactory.getLogger(PEPSFileMetadataProcessor.class.getName());
    Map<String, String> directoryToDescriptor=new HashMap<String, String>();
    /**
     * @return a list of entity decriptors read from the current directory (repositoryPath)
     */
    public List<EntityDescriptor> getEntityDescriptors(){
        List<EntityDescriptor> list=new ArrayList<EntityDescriptor>();
        List<String> files=getFiles();
        for(String fileName:files){
            EntityDescriptor descriptor=loadDescriptor(fileName);
            if(descriptor!=null){
                list.add(descriptor);
                directoryToDescriptor.put(fileName, descriptor.getEntityID());
            }
        }
        return list;
    }
    public String getRepositoryPath() {
        return repositoryPath;
    }

    public void setRepositoryPath(String repositoryPath) {
        this.repositoryPath = repositoryPath;
        fileService.setRepositoryDir(repositoryPath);
        initFileMonitor();
    }

    private List<String> getFiles(){
        return fileService.getFileList(false);
    }
    private EntityDescriptor loadDescriptor(String fileName){
        byte[] content = fileService.loadBinaryFile(fileName);
        return content==null?null : metadataTool.deserializeEntityDescriptor(new String(content));
    }

    private void initFileMonitor(){
        if(fileService!=null && fileService.existsFile(".")) {
            try {
                monitor=new FileAlterationMonitor(MONITOR_INTERVAL);
                observer = new FileAlterationObserver(fileService.getRepositoryDir());
                xmlObserver=new XMLObserver();
                observer.addListener(xmlObserver);
                monitor.addObserver(observer);
                monitor.start();
            } catch (Exception e) {
                LOG.error("fail to stop file monitor {}", e);
            }
        }
    }

    List<IStaticMetadataChangeListener> listeners=new ArrayList<IStaticMetadataChangeListener>();
    public void addListenerContentChanged( IStaticMetadataChangeListener listener){
        listeners.add(listener);
    }
    @Override
    public void onApplicationEvent(ApplicationEvent applicationEvent) {
        if(applicationEvent instanceof ContextClosedEvent || applicationEvent instanceof ContextStoppedEvent){
            //stop worker thread
            if(monitor!=null){
                try {
                    monitor.stop();
                    monitor.removeObserver(observer);
                }catch(Exception e){
                    LOG.error("fail to stop file monitor {}", e);
                }
                monitor=null;
            }
        }
    }

    private class XMLObserver implements FileAlterationListener {
        @Override
        public void onFileCreate(File file) {
            LOG.debug("file " + file.getName() + " created");
            EntityDescriptor ed = loadDescriptor(file.getName());
            if(ed!=null) {
                for (IStaticMetadataChangeListener listener : listeners) {
                    listener.add(ed);
                }
            }
        }

        @Override
        public void onFileChange(File file) {
            EntityDescriptor ed = loadDescriptor(file.getName());
            if(ed!=null) {
                for (IStaticMetadataChangeListener listener : listeners) {
                    if(directoryToDescriptor.containsKey(file.getName())) {
                        listener.remove(directoryToDescriptor.get(file.getName()));
                    }
                    listener.add(ed);
                }
            }
        }

        @Override
        public void onFileDelete(File file) {
            LOG.debug("file "+file.getName()+" changed");
            if(directoryToDescriptor.containsKey(file.getName())) {
                for (IStaticMetadataChangeListener listener : listeners) {
                    listener.remove(directoryToDescriptor.get(file.getName()));
                }
            }
        }

        @Override
        public void onStart(FileAlterationObserver fileAlterationObserver) {

        }

        @Override
        public void onDirectoryCreate(File file) {

        }

        @Override
        public void onDirectoryChange(File file) {

        }

        @Override
        public void onDirectoryDelete(File file) {

        }

        @Override
        public void onStop(FileAlterationObserver fileAlterationObserver) {

        }
    }
}
