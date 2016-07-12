package eu.eidas.auth.commons.session;

import java.io.ObjectStreamException;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import eu.eidas.auth.commons.IEIDASSession;
import eu.eidas.auth.commons.protocol.IAuthenticationRequest;

/**
 * Represents a type attribute stored in the eIDAS session.
 * <p>
 * <b><u>Note:</u><b> This implementation uses a typesafe enum (Effective Java - item 21) holding all available
 * constants.
 *
 * @param <T> the type of the attribute
 */
public final class TypedSessionAttribute<T> implements EidasSessionAttribute<T>, Serializable {

    private static final long serialVersionUID = -3524093852285199792L;

    /**
     * Represents the 'authnRequest' session attribute issued by the Connector.
     */
    public static final EidasSessionAttribute<IAuthenticationRequest> CONNECTOR_AUTHN_REQUEST =
            new TypedSessionAttribute<IAuthenticationRequest>("connectorAuthnRequest");

    /**
     * Represents the 'errorRedirectUrl' session attribute.
     */
    public static final EidasSessionAttribute<String> ERROR_REDIRECT_URL =
            new TypedSessionAttribute<String>("errorRedirectUrl");


    /**
     * Represents the 'relay state' session attribute.
     */
    public static final EidasSessionAttribute<String> RELAY_STATE = new TypedSessionAttribute<String>("relayState");


    /**
     * Represents the 'remote address' session attribute.
     */
    public static final EidasSessionAttribute<String> REMOTE_ADDRESS =
            new TypedSessionAttribute<String>("remoteAddress");

    /**
     * Represents the 'inResponseTo' session attribute.
     */
    public static final EidasSessionAttribute<String> SAML_IN_RESPONSE_TO =
            new TypedSessionAttribute<String>("inResponseTo");

    /**
     * Represents the 'authnRequest' session attribute issued by the Service Provider.
     */
    public static final EidasSessionAttribute<IAuthenticationRequest> SERVICE_PROVIDER_AUTHN_REQUEST =
            new TypedSessionAttribute<IAuthenticationRequest>("spAuthnRequest");

    /**
     * Represents the 'spUrl' session attribute.
     */
    public static final EidasSessionAttribute<String> SP_URL = new TypedSessionAttribute<String>("spUrl");

    @Nonnull
    private final transient String name;

    private TypedSessionAttribute(@Nonnull String name) {
        this.name = name;
    }

    @Override
    public final boolean exists(@Nonnull IEIDASSession session) {
        return null != get(session);
    }

    @Nullable
    @Override
    public final T get(@Nonnull IEIDASSession session) {
        //noinspection unchecked
        return (T) session.get(getName());
    }

    @Nonnull
    @Override
    public final String getName() {
        return name;
    }

    @Override
    public final void remove(@Nonnull IEIDASSession session) {
        session.remove(this);
    }

    @Override
    public final void set(@Nonnull IEIDASSession session, @Nullable T value) {
        if (null == value) {
            return;
        }
        session.put(getName(), value);
    }

    @Override
    public final String toString() {
        return getName();
    }

    private static final int PUBLIC_STATIC_FINAL = Modifier.PUBLIC | Modifier.STATIC | Modifier.FINAL;

    private static boolean isPublicStaticFinalModifier(int modifier) {
        return (modifier & PUBLIC_STATIC_FINAL) == PUBLIC_STATIC_FINAL;
    }

    // The 4 declarations below are necessary for serialization
    private static int nextOrdinal = 0;

    private final int ordinal = nextOrdinal++;

    /**
     * The order in the array MUST be the declaration order of the constants in the class.
     */
    private static final EidasSessionAttribute<?>[] VALUES = {
            CONNECTOR_AUTHN_REQUEST, ERROR_REDIRECT_URL, RELAY_STATE, REMOTE_ADDRESS, SAML_IN_RESPONSE_TO,
            SERVICE_PROVIDER_AUTHN_REQUEST, SP_URL};

    static {
        // Sanity check: ensures that all typesafe enum constant fields have been declared into the VALUES array used for serialization
        try {
            Set<EidasSessionAttribute<?>> values = new LinkedHashSet<>();
            // Unfortunately the order of the fields is JVM-dependent
            Field[] fields = TypedSessionAttribute.class.getFields();
            for (final Field field : fields) {
                if (EidasSessionAttribute.class.isAssignableFrom(field.getType()) && isPublicStaticFinalModifier(
                        field.getModifiers())) {
                    values.add((EidasSessionAttribute<?>) field.get(TypedSessionAttribute.class));
                }
            }

            Set<EidasSessionAttribute<?>> existingValues = new LinkedHashSet<>();
            Collections.addAll(existingValues, VALUES);

            if (!values.equals(existingValues)) {
                throw new AssertionError("Missing typesafe enum constants " + values.removeAll(existingValues) + " in "
                                                 + TypedSessionAttribute.class.getName() + "#VALUES field");
            }
        } catch (IllegalAccessException iae) {
            throw new AssertionError(iae);
        }
    }

    Object readResolve() throws ObjectStreamException {
        return VALUES[ordinal]; // Canonicalize
    }
}
