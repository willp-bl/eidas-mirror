package eu.eidas.auth.commons.session;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import eu.eidas.auth.commons.IEIDASSession;

/**
 * An Attribute stored in the {@link IEIDASSession}.
 *
 * @param <T> the type of this attribute.
 * @since 1.1
 */
public interface EidasSessionAttribute<T> {

    boolean exists(@Nonnull IEIDASSession session);

    @Nullable
    T get(@Nonnull IEIDASSession session);

    @Nonnull
    String getName();

    void remove(@Nonnull IEIDASSession session);

    void set(@Nonnull IEIDASSession session, @Nonnull T val);
}
