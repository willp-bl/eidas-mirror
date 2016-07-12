package eu.eidas.auth.engine.core.eidas;

/**
 * PersonType
 *
 * @since 1.1
 */
enum PersonType {
    NATURAL_PERSON("naturalperson"),
    LEGAL_PERSON("legalperson");

    private final transient String type;

    PersonType(String type) {
        this.type = type;
    }

    String getType() {
        return type;
    }
}
