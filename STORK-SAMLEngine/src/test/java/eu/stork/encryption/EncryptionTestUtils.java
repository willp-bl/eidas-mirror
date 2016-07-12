package eu.stork.encryption;

import eu.stork.peps.auth.engine.core.RequestedAttribute;
import eu.stork.peps.auth.engine.core.stork.*;
import eu.stork.peps.auth.engine.core.stork.impl.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.impl.RequestedAttributeBuilder;
import org.opensaml.saml2.metadata.impl.RequestedAttributeMarshaller;
import org.opensaml.saml2.metadata.impl.RequestedAttributeUnmarshaller;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.schema.impl.XSAnyMarshaller;
import org.opensaml.xml.schema.impl.XSAnyUnmarshaller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.Security;

/**
 * Created by bodabel on 11/12/2014.
 */
public class EncryptionTestUtils {

    private static final Logger log = LoggerFactory
            .getLogger(EncryptionTestUtils.class.getName());

    public static void initXMLTolling() {

        log.debug("Init XMLTooling... register SAML 2.0 providers");
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new RuntimeException(e);
        }

        log.debug("Init XMLTooling... register STORK objects XML provider");
        Configuration.registerObjectProvider(QAAAttribute.DEF_ELEMENT_NAME,
                new QAAAttributeBuilder(), new QAAAttributeMarshaller(),
                new QAAAttributeUnmarshaller());

        Configuration.registerObjectProvider(EIDSectorShare.DEF_ELEMENT_NAME,
                new EIDSectorShareBuilder(), new EIDSectorShareMarshaller(),
                new EIDSectorShareUnmarshaller());

        Configuration.registerObjectProvider(
                EIDCrossSectorShare.DEF_ELEMENT_NAME,
                new EIDCrossSectorShareBuilder(),
                new EIDCrossSectorShareMarshaller(),
                new EIDCrossSectorShareUnmarshaller());

        Configuration.registerObjectProvider(
                EIDCrossBorderShare.DEF_ELEMENT_NAME,
                new EIDCrossBorderShareBuilder(),
                new EIDCrossBorderShareMarshaller(),
                new EIDCrossBorderShareUnmarshaller());

        Configuration.registerObjectProvider(SPSector.DEF_ELEMENT_NAME,
                new SPSectorBuilder(), new SPSectorMarshaller(),
                new SPSectorUnmarshaller());

        Configuration.registerObjectProvider(SPInstitution.DEF_ELEMENT_NAME,
                new SPInstitutionBuilder(), new SPInstitutionMarshaller(),
                new SPInstitutionUnmarshaller());

        Configuration.registerObjectProvider(SPApplication.DEF_ELEMENT_NAME,
                new SPApplicationBuilder(), new SPApplicationMarshaller(),
                new SPApplicationUnmarshaller());

        Configuration.registerObjectProvider(SPCountry.DEF_ELEMENT_NAME,
                new SPCountryBuilder(), new SPCountryMarshaller(),
                new SPCountryUnmarshaller());

        Configuration.registerObjectProvider(XSAny.TYPE_NAME,
                new XSAnyBuilder(), new XSAnyMarshaller(),
                new XSAnyUnmarshaller());

        Configuration.registerObjectProvider(
                eu.stork.peps.auth.engine.core.stork.RequestedAttribute.DEF_ELEMENT_NAME,
                new RequestedAttributeBuilder(),
                new RequestedAttributeMarshaller(),
                new RequestedAttributeUnmarshaller());

        Configuration.registerObjectProvider(
                RequestedAttributes.DEF_ELEMENT_NAME,
                new RequestedAttributesBuilder(),
                new RequestedAttributesMarshaller(),
                new RequestedAttributesUnmarshaller());

        Configuration.registerObjectProvider(
                AuthenticationAttributes.DEF_ELEMENT_NAME,
                new AuthenticationAttributesBuilder(),
                new AuthenticationAttributesMarshaller(),
                new AuthenticationAttributesUnmarshaller());

        Configuration.registerObjectProvider(
                VIDPAuthenticationAttributes.DEF_ELEMENT_NAME,
                new VIDPAuthenticationAttributesBuilder(),
                new VIDPAuthenticationAttributesMarshaller(),
                new VIDPAuthenticationAttributesUnmarshaller());

        Configuration.registerObjectProvider(
                CitizenCountryCode.DEF_ELEMENT_NAME,
                new CitizenCountryCodeBuilder(),
                new CitizenCountryCodeMarshaller(),
                new CitizenCountryCodeUnmarshaller());

        Configuration.registerObjectProvider(
                SPID.DEF_ELEMENT_NAME,
                new SPIDBuilder(),
                new SPIDMarshaller(),
                new SPIDUnmarshaller());

        Configuration.registerObjectProvider(
                SPInformation.DEF_ELEMENT_NAME,
                new SPInformationBuilder(),
                new SPInformationMarshaller(),
                new SPInformationUnmarshaller());

        log.debug("Init XMLTooling... register security providers");
        // Dynamically register Bouncy Castle provider.
        boolean found = false;
        // Check if BouncyCastle is already registered as a provider
        final Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {
            if (providers[i].getName().equals(
                    BouncyCastleProvider.PROVIDER_NAME)) {
                found = true;
            }
        }
        // Register only if the provider has not been previously registered
        if (!found) {
            Security.insertProviderAt(new BouncyCastleProvider(), 0);
        }
    }
}
