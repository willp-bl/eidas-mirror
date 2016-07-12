package eu.eidas.auth.commons.protocol.eidas.impl;

import javax.annotation.Nonnull;

import eu.eidas.auth.commons.attribute.impl.AbstractAttributeValue;

/**
 * eIDAS PostalAddress AttributeValue
 *
 * @since 1.1
 */
public final class PostalAddressAttributeValue extends AbstractAttributeValue<PostalAddress> {

    public PostalAddressAttributeValue(@Nonnull PostalAddress value) {
        super(value, false);
    }
}
