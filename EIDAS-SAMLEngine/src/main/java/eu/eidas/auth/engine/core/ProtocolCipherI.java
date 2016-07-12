package eu.eidas.auth.engine.core;

/**
 * Marker interface for the encrypt and decrypt interfaces.
 *
 * @since 1.1
 */
public interface ProtocolCipherI {

    boolean isCheckedValidityPeriod();

    boolean isDisallowedSelfSignedCertificate();

    /**
     * Returns whether encryption is mandatory regardless of the country.
     * <p>
     * When this flag is {@code true}, the {@link #isEncryptionEnabled(String)} method must always return {@code true}.
     *
     * @return whether encryption is mandatory regardless of the country.
     */
    boolean isResponseEncryptionMandatory();
}
