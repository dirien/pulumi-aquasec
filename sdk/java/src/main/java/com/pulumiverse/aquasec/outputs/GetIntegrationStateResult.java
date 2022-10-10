// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumiverse.aquasec.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetIntegrationStateResult {
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return OIDCSettings enabled status
     * 
     */
    private final Boolean oidcSettings;
    /**
     * @return OpenIdSettings enabled status
     * 
     */
    private final Boolean openidSettings;
    /**
     * @return SAMLSettings enabled status
     * 
     */
    private final Boolean samlSettings;

    @CustomType.Constructor
    private GetIntegrationStateResult(
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("oidcSettings") Boolean oidcSettings,
        @CustomType.Parameter("openidSettings") Boolean openidSettings,
        @CustomType.Parameter("samlSettings") Boolean samlSettings) {
        this.id = id;
        this.oidcSettings = oidcSettings;
        this.openidSettings = openidSettings;
        this.samlSettings = samlSettings;
    }

    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return OIDCSettings enabled status
     * 
     */
    public Boolean oidcSettings() {
        return this.oidcSettings;
    }
    /**
     * @return OpenIdSettings enabled status
     * 
     */
    public Boolean openidSettings() {
        return this.openidSettings;
    }
    /**
     * @return SAMLSettings enabled status
     * 
     */
    public Boolean samlSettings() {
        return this.samlSettings;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIntegrationStateResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String id;
        private Boolean oidcSettings;
        private Boolean openidSettings;
        private Boolean samlSettings;

        public Builder() {
    	      // Empty
        }

        public Builder(GetIntegrationStateResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.oidcSettings = defaults.oidcSettings;
    	      this.openidSettings = defaults.openidSettings;
    	      this.samlSettings = defaults.samlSettings;
        }

        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder oidcSettings(Boolean oidcSettings) {
            this.oidcSettings = Objects.requireNonNull(oidcSettings);
            return this;
        }
        public Builder openidSettings(Boolean openidSettings) {
            this.openidSettings = Objects.requireNonNull(openidSettings);
            return this;
        }
        public Builder samlSettings(Boolean samlSettings) {
            this.samlSettings = Objects.requireNonNull(samlSettings);
            return this;
        }        public GetIntegrationStateResult build() {
            return new GetIntegrationStateResult(id, oidcSettings, openidSettings, samlSettings);
        }
    }
}
