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
    public static class GetIntegrationState
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
        ///     var integrationState = Aquasec.GetIntegrationState.Invoke();
        /// 
        ///     return new Dictionary&lt;string, object?&gt;
        ///     {
        ///         ["aquasecIntegrationState"] = integrationState,
        ///     };
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetIntegrationStateResult> InvokeAsync(InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetIntegrationStateResult>("aquasec:index/getIntegrationState:getIntegrationState", InvokeArgs.Empty, options.WithDefaults());

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
        ///     var integrationState = Aquasec.GetIntegrationState.Invoke();
        /// 
        ///     return new Dictionary&lt;string, object?&gt;
        ///     {
        ///         ["aquasecIntegrationState"] = integrationState,
        ///     };
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetIntegrationStateResult> Invoke(InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetIntegrationStateResult>("aquasec:index/getIntegrationState:getIntegrationState", InvokeArgs.Empty, options.WithDefaults());
    }


    [OutputType]
    public sealed class GetIntegrationStateResult
    {
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// OIDCSettings enabled status
        /// </summary>
        public readonly bool OidcSettings;
        /// <summary>
        /// OpenIdSettings enabled status
        /// </summary>
        public readonly bool OpenidSettings;
        /// <summary>
        /// SAMLSettings enabled status
        /// </summary>
        public readonly bool SamlSettings;

        [OutputConstructor]
        private GetIntegrationStateResult(
            string id,

            bool oidcSettings,

            bool openidSettings,

            bool samlSettings)
        {
            Id = id;
            OidcSettings = oidcSettings;
            OpenidSettings = openidSettings;
            SamlSettings = samlSettings;
        }
    }
}
