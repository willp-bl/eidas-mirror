package eu.eidas.auth.commons.protocol.eidas.impl;

import javax.annotation.Nonnull;

import eu.eidas.auth.commons.EidasStringUtil;
import eu.eidas.auth.commons.attribute.AttributeValue;

import static org.junit.Assert.assertEquals;

/**
 * PostalAddressAttributeValueMarshallerTest
 *
 * @since 1.1
 */
abstract class PostalAddressAttributeValueMarshallerTest {

    static PostalAddress newPostalAddress() {
        return PostalAddress.builder().
                cvAddressArea("addressAreaContentTest").
                poBox("1000").
                locatorDesignator("locatorDesignatorTest").
                locatorName("locatorNameTest").
                thoroughfare("thoroughfareTest").
                postName("postNameTest").
                adminUnitFirstLine("adminUnitFirstLine").
                adminUnitSecondLine("adminUnitSecondLine").
                postCode("postCodeTest").build();
    }

    static String toBase64Address(@Nonnull String prefix) {
        StringBuilder builder = new StringBuilder(150);

        builder.append("<").append(prefix).append(":PoBox>");
        builder.append("1000");
        builder.append("</").append(prefix).append(":PoBox>\n");

        builder.append("<").append(prefix).append(":LocatorDesignator>");
        builder.append("locatorDesignatorTest");
        builder.append("</").append(prefix).append(":LocatorDesignator>\n");

        builder.append("<").append(prefix).append(":LocatorName>");
        builder.append("locatorNameTest");
        builder.append("</").append(prefix).append(":LocatorName>\n");

        builder.append("<").append(prefix).append(":CvaddressArea>");
        builder.append("addressAreaContentTest");
        builder.append("</").append(prefix).append(":CvaddressArea>\n");

        builder.append("<").append(prefix).append(":Thoroughfare>");
        builder.append("thoroughfareTest");
        builder.append("</").append(prefix).append(":Thoroughfare>\n");

        builder.append("<").append(prefix).append(":PostName>");
        builder.append("postNameTest");
        builder.append("</").append(prefix).append(":PostName>\n");

        builder.append("<").append(prefix).append(":AdminunitFirstline>");
        builder.append("adminUnitFirstLine");
        builder.append("</").append(prefix).append(":AdminunitFirstline>\n");

        builder.append("<").append(prefix).append(":AdminunitSecondline>");
        builder.append("adminUnitSecondLine");
        builder.append("</").append(prefix).append(":AdminunitSecondline>\n");

        builder.append("<").append(prefix).append(":PostCode>");
        builder.append("postCodeTest");
        builder.append("</").append(prefix).append(":PostCode>\n");

        return EidasStringUtil.encodeToBase64(builder.toString());
    }

    @Nonnull
    private final AbstractPostalAddressAttributeValueMarshaller marshaller;

    protected PostalAddressAttributeValueMarshallerTest(@Nonnull AbstractPostalAddressAttributeValueMarshaller marshaller) {
        this.marshaller = marshaller;
    }

    protected void testMarshal() throws Exception {
        PostalAddress postalAddress = PostalAddressAttributeValueMarshallerTest.newPostalAddress();

        String result = marshaller.marshal(new PostalAddressAttributeValue(postalAddress));

        String base64String = PostalAddressAttributeValueMarshallerTest.toBase64Address(marshaller.getPrefix());
        assertEquals(EidasStringUtil.decodeStringFromBase64(base64String),
                     EidasStringUtil.decodeStringFromBase64(result));
        assertEquals(base64String, result);
    }

    protected void testUnmarshal() throws Exception {
        AttributeValue<PostalAddress> result =
                marshaller.unmarshal(PostalAddressAttributeValueMarshallerTest.toBase64Address(marshaller.getPrefix()), false);

        assertEquals(PostalAddressAttributeValueMarshallerTest.newPostalAddress(), result.getValue());
    }
}
