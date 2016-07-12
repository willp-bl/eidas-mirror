package eu.eidas.auth.commons.attribute.impl;

import javax.annotation.Nonnull;

/**
 * String AttributeValue
 *
 * @since 1.1
 */
public final class StringAttributeValue extends AbstractAttributeValue<String> {

    public StringAttributeValue(@Nonnull String value, boolean latinScript) {
        super(value, latinScript);
    }
}
