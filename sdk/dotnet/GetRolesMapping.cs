// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace Pulumiverse.Aquasec
{
    public static class GetRolesMapping
    {
        /// <summary>
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Aquasec = Pulumi.Aquasec;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var rolesMapping = Aquasec.GetRolesMapping.Invoke();
        /// 
        ///     return new Dictionary&lt;string, object?&gt;
        ///     {
        ///         ["roleMappingAll"] = rolesMapping,
        ///         ["roleMappingSaml"] = rolesMapping.Apply(getRolesMappingResult =&gt; getRolesMappingResult.Samls),
        ///     };
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetRolesMappingResult> InvokeAsync(InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetRolesMappingResult>("aquasec:index/getRolesMapping:getRolesMapping", InvokeArgs.Empty, options.WithDefaults());

        /// <summary>
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Aquasec = Pulumi.Aquasec;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var rolesMapping = Aquasec.GetRolesMapping.Invoke();
        /// 
        ///     return new Dictionary&lt;string, object?&gt;
        ///     {
        ///         ["roleMappingAll"] = rolesMapping,
        ///         ["roleMappingSaml"] = rolesMapping.Apply(getRolesMappingResult =&gt; getRolesMappingResult.Samls),
        ///     };
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetRolesMappingResult> Invoke(InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetRolesMappingResult>("aquasec:index/getRolesMapping:getRolesMapping", InvokeArgs.Empty, options.WithDefaults());
    }


    [OutputType]
    public sealed class GetRolesMappingResult
    {
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// LDAP Authentication
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRolesMappingLdapResult> Ldaps;
        /// <summary>
        /// Oauth2 Authentication
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRolesMappingOauth2Result> Oauth2s;
        /// <summary>
        /// OpenId Authentication
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRolesMappingOpenidResult> Openids;
        /// <summary>
        /// SAML Authentication
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRolesMappingSamlResult> Samls;

        [OutputConstructor]
        private GetRolesMappingResult(
            string id,

            ImmutableArray<Outputs.GetRolesMappingLdapResult> ldaps,

            ImmutableArray<Outputs.GetRolesMappingOauth2Result> oauth2s,

            ImmutableArray<Outputs.GetRolesMappingOpenidResult> openids,

            ImmutableArray<Outputs.GetRolesMappingSamlResult> samls)
        {
            Id = id;
            Ldaps = ldaps;
            Oauth2s = oauth2s;
            Openids = openids;
            Samls = samls;
        }
    }
}
