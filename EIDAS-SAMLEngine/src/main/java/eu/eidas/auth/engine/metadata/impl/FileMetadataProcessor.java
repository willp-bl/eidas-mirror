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
package eu.eidas.auth.engine.metadata.impl;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import eu.eidas.auth.engine.metadata.IStaticMetadataChangeListener;
import eu.eidas.auth.engine.metadata.MetadataProcessorI;
import org.apache.commons.io.monitor.FileAlterationListener;
import org.apache.commons.io.monitor.FileAlterationMonitor;
import org.apache.commons.io.monitor.FileAlterationObserver;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.ContextStoppedEvent;

import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.engine.metadata.EntityDescriptorContainer;
import eu.eidas.auth.engine.metadata.MetadataGenerator;
import eu.eidas.auth.engine.xml.opensaml.SAMLBootstrap;
import eu.eidas.impl.file.FileService;

/**
 * implements metadata cache
 * the source metadata: all readable xml files found in a configured directory
 */
public class FileMetadataProcessor implements ApplicationListener, MetadataProcessorI {
    private String repositoryPath;
    private FileService fileService = new FileService();
    private MetadataGenerator metadataTool=new MetadataGenerator();
    /**
     * monitor the folder for changes on the files
     * @deprecated use the java 7 {@link java.nio.file.FileSystem#newWatchService()} instead, which implements this natively, is thread-safe and does not start a Thread (which is forbidden on WebSphere and on the Google App Engine).
     */
    private FileAlterationMonitor monitor;

    /**
     * @deprecated use the java 7 {@link java.nio.file.FileSystem#newWatchService()} instead, which implements this natively, is thread-safe and does not start a Thread (which is forbidden on WebSphere and on the Google App Engine).
     */
    private FileAlterationObserver observer;
    private XMLObserver xmlObserver;
    private static final long MONITOR_INTERVAL=1000L;
    private static final Logger LOG = LoggerFactory.getLogger(FileMetadataProcessor.class.getName());
    private boolean init=false;
    private Map<String, List<String>> directoryToDescriptor=new HashMap<String, List<String>>();
    /**
     * @deprecated use the java 7 {@link java.nio.file.FileSystem#newWatchService()} instead, which implements this natively, is thread-safe and does not start a Thread (which is forbidden on WebSphere and on the Google App Engine).
     */
    private ScheduledThreadPoolExecutor stpe=null;
    private Runnable refreshCommand=null;

    /**
     * @return a list of entity descriptors read from the current directory (repositoryPath)
     */
    public List<EntityDescriptorContainer> getEntityDescriptors(){
    	if(!init){
    		init=true;
    		try{
    		SAMLBootstrap.bootstrap();
    		}catch(ConfigurationException ce){
    			LOG.error("error bootstraping opensaml {}", ce);
    		}
    	}
        List<EntityDescriptorContainer> list=new ArrayList<EntityDescriptorContainer>();
        List<String> files=getFiles();
        for(String fileName:files){
        	EntityDescriptorContainer descriptors=loadDescriptors(fileName);
            if(descriptors!=null){
                list.add(descriptors);
                List<String> ids=new ArrayList<String>();
                for(EntityDescriptor ed:descriptors.getEntityDescriptors()){
                	ids.add(ed.getEntityID());
                }
            	directoryToDescriptor.put(fileName, ids);
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
    private EntityDescriptorContainer loadDescriptors(String fileName){
        byte[] content = fileService.loadBinaryFile(fileName);
        return content==null?null : metadataTool.deserializeEntityDescriptor(EidasStringUtil.toString(content));
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

                //periodically refresh static metadata
                stpe=new ScheduledThreadPoolExecutor(1);
                refreshCommand=new RefreshStaticMetadata(xmlObserver, fileService);
                //TODO externalize the interval between refreshes in the property file
                stpe.scheduleAtFixedRate(refreshCommand, 1, 24, TimeUnit.HOURS);

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
        	endMonitoring();
        }
    }

    public void endMonitoring(){
        //stop worker thread
        if(monitor!=null){
            try {
                monitor.stop();
                monitor.removeObserver(observer);
                stpe.shutdown();
            }catch(Exception e){
                LOG.error("fail to stop file monitor {}", e);
            }
            monitor=null;
        }

    }

    /**
     * Runnable to refresh static metadata
     */
    private class RefreshStaticMetadata implements Runnable{
        private XMLObserver observer;
        private FileService fileService;
        RefreshStaticMetadata(XMLObserver observer, FileService fileService){
            this.observer=observer;
            this.fileService=fileService;
        }
        @Override
        public void run() {
            List<String> fileList=fileService.getFileList(false);
            for(String fileName:fileList){
                observer.onFileChange(new File(fileName));
            }
        }
    }

    /**
     * observer of the directory containing the static metadata.
     * it reacts to the changes in the file list or file updates, performing refresh of the cache.
     */
    private class XMLObserver implements FileAlterationListener {
        @Override
        public void onFileCreate(File file) {
            LOG.debug("file " + file.getName() + " created");
            /*EntityDescriptorContainer eds = loadDescriptors(file.getName());
            if(eds!=null) {
            	for(EntityDescriptor ed: eds.getEntityDescriptors()){
	                for (IStaticMetadataChangeListener listener : listeners) {
	                    listener.add(ed);
	                }
            	}
            }*/
        }

        @Override
        public void onFileChange(File file) {
        	EntityDescriptorContainer eds = loadDescriptors(file.getName());
            if(eds!=null) {
            	for(EntityDescriptor ed: eds.getEntityDescriptors()){
	                for (IStaticMetadataChangeListener listener : listeners) {
	                    if(directoryToDescriptor.containsKey(file.getName())) {
	                    	List<String> ids=directoryToDescriptor.get(file.getName());
	                    	for(String id:ids){
	                    		listener.remove(id);
	                    	}
	                    }
	                }
            	}
            }
        }

        @Override
        public void onFileDelete(File file) {
            LOG.debug("file "+file.getName()+" changed");
            if(directoryToDescriptor.containsKey(file.getName())) {
                for (IStaticMetadataChangeListener listener : listeners) {
                    if(directoryToDescriptor.containsKey(file.getName())) {
                    	List<String> ids=directoryToDescriptor.get(file.getName());
                    	for(String id:ids){
                    		listener.remove(id);
                    	}
                    }
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
