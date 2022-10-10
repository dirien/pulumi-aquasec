// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumiverse.aquasec.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumiverse.aquasec.outputs.KubernetesAssurancePolicyScopeVariable;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class KubernetesAssurancePolicyScope {
    private final @Nullable String expression;
    private final @Nullable List<KubernetesAssurancePolicyScopeVariable> variables;

    @CustomType.Constructor
    private KubernetesAssurancePolicyScope(
        @CustomType.Parameter("expression") @Nullable String expression,
        @CustomType.Parameter("variables") @Nullable List<KubernetesAssurancePolicyScopeVariable> variables) {
        this.expression = expression;
        this.variables = variables;
    }

    public Optional<String> expression() {
        return Optional.ofNullable(this.expression);
    }
    public List<KubernetesAssurancePolicyScopeVariable> variables() {
        return this.variables == null ? List.of() : this.variables;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(KubernetesAssurancePolicyScope defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String expression;
        private @Nullable List<KubernetesAssurancePolicyScopeVariable> variables;

        public Builder() {
    	      // Empty
        }

        public Builder(KubernetesAssurancePolicyScope defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.expression = defaults.expression;
    	      this.variables = defaults.variables;
        }

        public Builder expression(@Nullable String expression) {
            this.expression = expression;
            return this;
        }
        public Builder variables(@Nullable List<KubernetesAssurancePolicyScopeVariable> variables) {
            this.variables = variables;
            return this;
        }
        public Builder variables(KubernetesAssurancePolicyScopeVariable... variables) {
            return variables(List.of(variables));
        }        public KubernetesAssurancePolicyScope build() {
            return new KubernetesAssurancePolicyScope(expression, variables);
        }
    }
}
