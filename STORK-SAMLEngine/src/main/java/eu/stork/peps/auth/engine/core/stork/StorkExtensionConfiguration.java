package eu.stork.peps.auth.engine.core.stork;

import eu.stork.peps.auth.engine.core.stork.impl.*;
import org.opensaml.Configuration;

public class StorkExtensionConfiguration {
    public void configureExtension(){
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
        Configuration.registerObjectProvider(
                RequestedAttribute.DEF_ELEMENT_NAME,
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


    }
}
