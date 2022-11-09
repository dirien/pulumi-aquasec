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
    public static class GetGateways
    {
        /// <summary>
        /// The data source `aquasec.getGateways` provides a method to query all gateways within the Aqua
        /// </summary>
        public static Task<GetGatewaysResult> InvokeAsync(InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetGatewaysResult>("aquasec:index/getGateways:getGateways", InvokeArgs.Empty, options.WithDefaults());
    }


    [OutputType]
    public sealed class GetGatewaysResult
    {
        /// <summary>
        /// A list of existing gateways' parameters.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetGatewaysGatewayResult> Gateways;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetGatewaysResult(
            ImmutableArray<Outputs.GetGatewaysGatewayResult> gateways,

            string id)
        {
            Gateways = gateways;
            Id = id;
        }
    }
}
