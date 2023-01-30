// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumiverse.aquasec.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumiverse.aquasec.outputs.GetRolesMappingLdap;
import com.pulumiverse.aquasec.outputs.GetRolesMappingOauth2;
import com.pulumiverse.aquasec.outputs.GetRolesMappingOpenid;
import com.pulumiverse.aquasec.outputs.GetRolesMappingSaml;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRolesMappingResult {
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return LDAP Authentication
     * 
     */
    private List<GetRolesMappingLdap> ldaps;
    /**
     * @return Oauth2 Authentication
     * 
     */
    private List<GetRolesMappingOauth2> oauth2s;
    /**
     * @return OpenId Authentication
     * 
     */
    private List<GetRolesMappingOpenid> openids;
    /**
     * @return SAML Authentication
     * 
     */
    private List<GetRolesMappingSaml> samls;

    private GetRolesMappingResult() {}
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return LDAP Authentication
     * 
     */
    public List<GetRolesMappingLdap> ldaps() {
        return this.ldaps;
    }
    /**
     * @return Oauth2 Authentication
     * 
     */
    public List<GetRolesMappingOauth2> oauth2s() {
        return this.oauth2s;
    }
    /**
     * @return OpenId Authentication
     * 
     */
    public List<GetRolesMappingOpenid> openids() {
        return this.openids;
    }
    /**
     * @return SAML Authentication
     * 
     */
    public List<GetRolesMappingSaml> samls() {
        return this.samls;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRolesMappingResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private List<GetRolesMappingLdap> ldaps;
        private List<GetRolesMappingOauth2> oauth2s;
        private List<GetRolesMappingOpenid> openids;
        private List<GetRolesMappingSaml> samls;
        public Builder() {}
        public Builder(GetRolesMappingResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.ldaps = defaults.ldaps;
    	      this.oauth2s = defaults.oauth2s;
    	      this.openids = defaults.openids;
    	      this.samls = defaults.samls;
        }

        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder ldaps(List<GetRolesMappingLdap> ldaps) {
            this.ldaps = Objects.requireNonNull(ldaps);
            return this;
        }
        public Builder ldaps(GetRolesMappingLdap... ldaps) {
            return ldaps(List.of(ldaps));
        }
        @CustomType.Setter
        public Builder oauth2s(List<GetRolesMappingOauth2> oauth2s) {
            this.oauth2s = Objects.requireNonNull(oauth2s);
            return this;
        }
        public Builder oauth2s(GetRolesMappingOauth2... oauth2s) {
            return oauth2s(List.of(oauth2s));
        }
        @CustomType.Setter
        public Builder openids(List<GetRolesMappingOpenid> openids) {
            this.openids = Objects.requireNonNull(openids);
            return this;
        }
        public Builder openids(GetRolesMappingOpenid... openids) {
            return openids(List.of(openids));
        }
        @CustomType.Setter
        public Builder samls(List<GetRolesMappingSaml> samls) {
            this.samls = Objects.requireNonNull(samls);
            return this;
        }
        public Builder samls(GetRolesMappingSaml... samls) {
            return samls(List.of(samls));
        }
        public GetRolesMappingResult build() {
            final var o = new GetRolesMappingResult();
            o.id = id;
            o.ldaps = ldaps;
            o.oauth2s = oauth2s;
            o.openids = openids;
            o.samls = samls;
            return o;
        }
    }
}
