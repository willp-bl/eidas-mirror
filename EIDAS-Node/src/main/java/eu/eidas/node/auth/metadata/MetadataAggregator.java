package eu.eidas.node.auth.metadata;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Properties;

import org.apache.commons.io.IOUtils;
import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.signature.SignableXMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.xml.opensaml.OpenSamlHelper;
import eu.eidas.auth.engine.ProtocolEngineFactory;
import eu.eidas.auth.engine.ProtocolEngineI;
import eu.eidas.auth.engine.configuration.dom.DOMConfigurationParser;
import eu.eidas.auth.engine.configuration.dom.ProtocolEngineConfigurationFactory;
import eu.eidas.auth.engine.metadata.EntityDescriptorContainer;
import eu.eidas.auth.engine.metadata.MetadataGenerator;
import eu.eidas.auth.engine.metadata.MetadataSignerI;
import eu.eidas.auth.engine.xml.opensaml.SAMLBootstrap;
import eu.eidas.engine.exceptions.EIDASSAMLEngineException;
import eu.eidas.impl.file.FileService;

/**
 * Command-line tool which allows to generate a file containing a EntitiesDescriptor, which will aggregate all
 * EntityDescriptor entities found in the files in the provided input directory
 * <p>
 * usage (for aggregation): MetadataAggregator output source_directory samlEngineConfigDirectory samlEngineName
 * outputFileName
 * <p>
 * where: - source_directory: the folder containing the xml files storing the entityDescriptors to aggregate -
 * samlEngineConfigDirectory is the complete path of a folder which has, under a subdirectory named SAMLEngine, a
 * complete SAML engine configuration - samlEngineName - the name of the samlEngine (e.g. Connector-Service) -
 * outputFileName - the name of the file containing the aggregation (in the current directory)
 */
public final class MetadataAggregator {

    private static final Logger LOGGER = LoggerFactory.getLogger(MetadataAggregator.class.getName());

    private static final String OPERATION_OUTPUT = "output";

    private static final String OPERATION_INPUT = "input";

    private static final String CONTROL_FILE_NAME = "eidas.xml";

    private static MetadataGenerator metadataTool = new MetadataGenerator();

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            System.out.println(
                    "usage: MetadataAggregator operation source_directory samlEngineConfigDirectory samlEngineName fileName");
            LOGGER.error("incorrect input parameters");
            return;
        }
        String operation = args[0];
        String sourceDirectory = args[1];
        String samlEngineConfig = args[2];
        String samlEngineName = args[3];
        String fileName = args[4];
        ApplicationContext ctx = new ClassPathXmlApplicationContext("filecertmgmt.xml");
        ProtocolEngineFactory protocolEngineFactory = new ProtocolEngineFactory(
                new ProtocolEngineConfigurationFactory(DOMConfigurationParser.DEFAULT_CONFIGURATION_FILE,
                                                       CONTROL_FILE_NAME));

        FileService fileService = (FileService) ctx.getBean("fileService");
        if (OPERATION_OUTPUT.equalsIgnoreCase(operation)) {
            createAggregateFile(fileService, protocolEngineFactory, samlEngineName, sourceDirectory, samlEngineConfig,
                                fileName);
        } else if (OPERATION_INPUT.equalsIgnoreCase(operation)) {
            try {
                SAMLBootstrap.bootstrap();
            } catch (ConfigurationException ce) {
                throw new IllegalStateException(ce);
            }
            checkEntitiesDescriptor(fileService, protocolEngineFactory, samlEngineName, samlEngineConfig, fileName);
        } else {
            System.out.println("neither input nor ouput operation modes selected");
            LOGGER.error("incorrect input parameters");
        }
        ((ConfigurableApplicationContext) ctx).close();
    }

    public static void createAggregateFile(FileService fileService,
                                           ProtocolEngineFactory protocolEngineFactory,
                                           String samlEngineName,
                                           String sourceDirectory,
                                           String samlEngineConfig,
                                           String outputFileName) {
        NODEFileMetadataProcessor processor = new NODEFileMetadataProcessor();
        processor.setRepositoryPath(sourceDirectory);
        List<EntityDescriptorContainer> list = processor.getEntityDescriptors();
        ProtocolEngineI engine = null;
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        EntitiesDescriptor eds = (EntitiesDescriptor) builderFactory.getBuilder(EntitiesDescriptor.DEFAULT_ELEMENT_NAME)
                .buildObject(EntitiesDescriptor.DEFAULT_ELEMENT_NAME);
        for (EntityDescriptorContainer edc : list) {
            eds.getEntityDescriptors().addAll(edc.getEntityDescriptors());
        }
        if (!fileService.existsFile(CONTROL_FILE_NAME)) {
            fileService.setRepositoryDir(samlEngineConfig);
        }
        Properties props = null;
        byte signedEds[] = null;
        String s = null;
        try {
            props = fileService.loadPropsFromXml("eidas.xml");
            engine = protocolEngineFactory.getProtocolEngine(samlEngineName);
            EntitiesDescriptor entitiesDescriptor = ((MetadataSignerI) engine.getSigner()).signMetadata(eds);
            signedEds = OpenSamlHelper.marshall(entitiesDescriptor);
            s = EidasStringUtil.toString(signedEds);
        } catch (EIDASSAMLEngineException ee) {
            LOGGER.error("error during sign {}", ee);
            return;
        } catch (Exception ex) {
            LOGGER.error("unexpected error during sign {}", ex);
            return;

        } finally {
            processor.endMonitoring();
        }
        FileOutputStream fos = null;
        try {
            File outputFile = new File(outputFileName);
            fos = new FileOutputStream(outputFile);
            if (s != null) {
                fos.write(s.getBytes("UTF-8"));
            }
        } catch (IOException ioe) {

            LOGGER.error("error writing the file");
            return;
        } finally {
            IOUtils.closeQuietly(fos);
        }
        checkEntitiesDescriptor(fileService, protocolEngineFactory, samlEngineName, samlEngineConfig, outputFileName);
    }

    private static void checkEntitiesDescriptor(FileService fileService,
                                                ProtocolEngineFactory protocolEngineFactory,
                                                String samlEngineName,
                                                String samlEngineConfig,
                                                String inputFileName) {
        FileInputStream fis = null;
        if (!fileService.existsFile("eidas.xml")) {
            fileService.setRepositoryDir(samlEngineConfig);
        }
        String s = null;
        try {
            File inputFile = new File(inputFileName);
            fis = new FileInputStream(inputFile);
            byte inputBytes[] = new byte[fis.available()];
            fis.read(inputBytes);
            s = EidasStringUtil.toString(inputBytes);
//			s=new String(fileService.loadBinaryFile(".\\"+inputFileName));
        } catch (IOException ioe) {
            LOGGER.error("error reading the file");
            return;
        } finally {
            IOUtils.closeQuietly(fis);
        }

        ProtocolEngineI engine = null;
        //check
        try {
            EntityDescriptorContainer edc = metadataTool.deserializeEntityDescriptor(s);
            engine = protocolEngineFactory.getProtocolEngine(samlEngineName);
            OpenSamlHelper.marshall(edc.getEntitiesDescriptor());
            SimpleMetadataCaching cache = new SimpleMetadataCaching();
            cache.putDescriptorSignatureHolder(OPERATION_INPUT, edc.getEntitiesDescriptor());
            SignableXMLObject signedObj = cache.getDescriptorSignatureHolder(OPERATION_INPUT);
            ((MetadataSignerI) engine.getSigner()).validateMetadataSignature(signedObj);
        } catch (Exception ex) {
            LOGGER.error("unexpected error during validation {}", ex);
            // TODO what about throwing an exception or returning a failure?
            throw new IllegalStateException(ex);
        }

    }

    private MetadataAggregator() {
    }
}
