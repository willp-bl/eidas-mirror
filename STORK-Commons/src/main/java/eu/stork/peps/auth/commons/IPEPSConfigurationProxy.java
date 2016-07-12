package eu.stork.peps.auth.commons;

/**
 * provides access to values of PEPS configuration parameters
 */
public interface IPEPSConfigurationProxy {
    /**
     *
     * @param parameterName the name of the PEPS parameter
     * @return the parameter value (or null if the parameter is missing from the config)
     */
    String getPepsParameterValue(String parameterName);
}
