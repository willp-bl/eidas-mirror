package eu.eidas.node.auth.metadata;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Properties;

import org.apache.commons.io.IOUtils;
import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.signature.SignableXMLObject;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import eu.eidas.auth.engine.EIDASSAMLEngine;
import eu.eidas.auth.engine.SAMLEngineUtils;
import eu.eidas.auth.engine.metadata.EntityDescriptorContainer;
import eu.eidas.auth.engine.metadata.MetadataGenerator;
import eu.eidas.configuration.SAMLBootstrap;
import eu.eidas.engine.exceptions.SAMLEngineException;
import eu.eidas.impl.file.FileService;
import eu.eidas.node.init.EidasSamlEngineFactory;
import eu.eidas.samlengineconfig.CertificateConfigurationManager;

/**
 * 
 * allows to generate a file containing a EntitiesDescriptor, which will aggregate
 * all EntityDescriptor entities found in the files in the provided input directory
 * 
 * usage (for aggregation):
 * MetadataAgregator output source_directory samlEngineConfigDirectory samlEngineName outputFileName
 * 
 * where:
 * - source_directory: the folder containing the xml files storing the entityDescriptors to aggregate
 * - samlEngineConfigDirectory is the complete path of a folder which has, under a subdirectory named SAMLEngine,
 * a complete SAML engine configuration
 * - samlEngineName - the name of the samlEngine (e.g. Connector-Service) 
 * - outputFileName - the name of the file containing the aggregation (in the current directory)
 *
 */

public class MetadataAgregator {
	final private static Logger LOGGER= LoggerFactory.getLogger(MetadataAgregator.class.getName());
	private static final String OPERATION_OUTPUT="output";
	private static final String OPERATION_INPUT="input";
	private static final String CONTROL_FILE_NAME="eidas.xml";
	private static MetadataGenerator metadataTool=new MetadataGenerator();

	public static void main(String[] args){
		if(args.length!=5){
			System.out.println("usage: MetadataAgregator operation source_directory samlEngineConfigDirectory samlEngineName fileName");
			LOGGER.error("incorrect input parameters");
			return;
		}
		String operation=args[0];
		String sourceDirectory=args[1];
		String samlEngineConfig=args[2];
		String samlEngineName=args[3];
		String fileName=args[4];
        ApplicationContext ctx=new ClassPathXmlApplicationContext("filecertmgmt.xml");
        EidasSamlEngineFactory engineFactory=new EidasSamlEngineFactory();
        CertificateConfigurationManager configManager=ctx.getBean(CertificateConfigurationManager.class);
        configManager.setLocation(samlEngineConfig);
        engineFactory.setEngineConfigurationProvider(configManager);
    	FileService fileService= (FileService)ctx.getBean("fileService");
    	if(OPERATION_OUTPUT.equalsIgnoreCase(operation)){
    		createAggregateFile(fileService, engineFactory, samlEngineName, sourceDirectory, samlEngineConfig, fileName);
    	}else if(OPERATION_INPUT.equalsIgnoreCase(operation)){
    		try{
    			SAMLBootstrap.bootstrap();
    		}catch(ConfigurationException ce){
    			
    		}
    		checkEntitiesDescriptor(fileService, engineFactory, samlEngineName, samlEngineConfig,fileName);
    	}else{
			System.out.println("neither input nor ouput operation modes selected");
			LOGGER.error("incorrect input parameters");
    	}
		((ConfigurableApplicationContext)ctx).close();
	}
	
	public static void createAggregateFile(FileService fileService, EidasSamlEngineFactory engineFactory, String samlEngineName, String sourceDirectory,String samlEngineConfig,String outputFileName){
        NODEFileMetadataProcessor processor=new NODEFileMetadataProcessor();
        processor.setRepositoryPath(sourceDirectory);
        List<EntityDescriptorContainer> list = processor.getEntityDescriptors();
        EIDASSAMLEngine engine=null;
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        EntitiesDescriptor eds = (EntitiesDescriptor)builderFactory.getBuilder(EntitiesDescriptor.DEFAULT_ELEMENT_NAME).buildObject(EntitiesDescriptor.DEFAULT_ELEMENT_NAME);
        for(EntityDescriptorContainer edc:list){
        	eds.getEntityDescriptors().addAll(edc.getEntityDescriptors());
        }
        if(!fileService.existsFile(CONTROL_FILE_NAME)){
        	fileService.setRepositoryDir(samlEngineConfig);
        }
        Properties props=null;
        byte signedEds[]=null;
        String s=null;
        try{
        	props = fileService.loadPropsFromXml("eidas.xml");
        	engine=engineFactory.getEngine(samlEngineName, props);
        	signedEds = engine.signAndMarshallEntitiesDescriptor(eds);
        	s=new String(signedEds, "UTF-8");
        }catch(SAMLEngineException ee){
        	LOGGER.error("error during sign {}", ee);
        	return;
        }catch(UnsupportedEncodingException uee){
        	LOGGER.error("encoding error {}", uee);
        }catch(Exception ex){
        	LOGGER.error("unexpected error during sign {}", ex);
        	return;
        	
        }finally{
    		processor.endMonitoring();
    		engineFactory.releaseEngine(engine);
        }
        FileOutputStream fos=null;
		try{
			File outputFile=new File(outputFileName);
			fos=new FileOutputStream(outputFile);
			if(s!=null) {
				fos.write(s.getBytes("UTF-8"));
			}
		}catch(IOException ioe){

			LOGGER.error("error writing the file");
			return;
		}finally{
			IOUtils.closeQuietly(fos);
		}
        checkEntitiesDescriptor(fileService, engineFactory, samlEngineName, samlEngineConfig, outputFileName);
	}
	
	private static void checkEntitiesDescriptor(FileService fileService, EidasSamlEngineFactory engineFactory, String samlEngineName,String samlEngineConfig,String inputFileName){
        FileInputStream fis=null;
        if(!fileService.existsFile("eidas.xml")){
        	fileService.setRepositoryDir(samlEngineConfig);
        }
        String s=null;
		try{
			File inputFile=new File(inputFileName);
			fis=new FileInputStream(inputFile);
			byte inputBytes[]=new byte[fis.available()];
			fis.read(inputBytes);
			s=new String(inputBytes, "UTF-8");
//			s=new String(fileService.loadBinaryFile(".\\"+inputFileName));
		}catch(IOException ioe){
			LOGGER.error("error reading the file");
			return;
		}finally{
			IOUtils.closeQuietly(fis);
		}


		EIDASSAMLEngine engine=null;
        //check
        try{
    		EntityDescriptorContainer edc=metadataTool.deserializeEntityDescriptor(s);
        	engine=engineFactory.getEngine(samlEngineName, null);
        	SAMLEngineUtils.serializeObject(edc.getEntitiesDescriptor());
        	SimpleMetadataCaching cache=new SimpleMetadataCaching();
        	cache.putDescriptorSignatureHolder(OPERATION_INPUT, edc.getEntitiesDescriptor());
    		SignableXMLObject signedObj=cache.getDescriptorSignatureHolder(OPERATION_INPUT);
        	SAMLEngineUtils.validateEntityDescriptorSignature(signedObj, engine);        	
        }catch(SAMLEngineException se){
        	LOGGER.error("unexpected error during validation {}", se);
        	return;
        }finally{
        	engineFactory.releaseEngine(engine);
        }
		
	}
}
