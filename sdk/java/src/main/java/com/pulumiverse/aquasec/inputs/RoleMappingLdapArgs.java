// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumiverse.aquasec.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Map;
import java.util.Objects;


public final class RoleMappingLdapArgs extends com.pulumi.resources.ResourceArgs {

    public static final RoleMappingLdapArgs Empty = new RoleMappingLdapArgs();

    /**
     * Role Mapping is used to define the IdP role that the user will assume in Aqua
     * 
     */
    @Import(name="roleMapping", required=true)
    private Output<Map<String,String>> roleMapping;

    /**
     * @return Role Mapping is used to define the IdP role that the user will assume in Aqua
     * 
     */
    public Output<Map<String,String>> roleMapping() {
        return this.roleMapping;
    }

    private RoleMappingLdapArgs() {}

    private RoleMappingLdapArgs(RoleMappingLdapArgs $) {
        this.roleMapping = $.roleMapping;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RoleMappingLdapArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RoleMappingLdapArgs $;

        public Builder() {
            $ = new RoleMappingLdapArgs();
        }

        public Builder(RoleMappingLdapArgs defaults) {
            $ = new RoleMappingLdapArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param roleMapping Role Mapping is used to define the IdP role that the user will assume in Aqua
         * 
         * @return builder
         * 
         */
        public Builder roleMapping(Output<Map<String,String>> roleMapping) {
            $.roleMapping = roleMapping;
            return this;
        }

        /**
         * @param roleMapping Role Mapping is used to define the IdP role that the user will assume in Aqua
         * 
         * @return builder
         * 
         */
        public Builder roleMapping(Map<String,String> roleMapping) {
            return roleMapping(Output.of(roleMapping));
        }

        public RoleMappingLdapArgs build() {
            $.roleMapping = Objects.requireNonNull($.roleMapping, "expected parameter 'roleMapping' to be non-null");
            return $;
        }
    }

}
