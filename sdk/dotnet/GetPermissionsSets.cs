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
    public static class GetPermissionsSets
    {
        /// <summary>
        /// The data source `aquasec.PermissionsSets` provides a method to query all permissions within the Aqua CSPMThe fields returned from this query are detailed in the Schema section below.
        /// 
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
        ///     var testpermissionsset = Aquasec.GetPermissionsSets.Invoke();
        /// 
        ///     return new Dictionary&lt;string, object?&gt;
        ///     {
        ///         ["permissionsSets"] = testpermissionsset.Apply(getPermissionsSetsResult =&gt; getPermissionsSetsResult),
        ///         ["permissionsSetsNames"] = new[]
        ///         {
        ///             testpermissionsset.Apply(getPermissionsSetsResult =&gt; getPermissionsSetsResult),
        ///         }.Select(__item =&gt; new[]
        ///         {
        ///             __item.Apply(obj =&gt; obj.PermissionsSets),
        ///         }.Select(__item =&gt; __item?.Name).ToList()).ToList(),
        ///     };
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetPermissionsSetsResult> InvokeAsync(InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetPermissionsSetsResult>("aquasec:index/getPermissionsSets:getPermissionsSets", InvokeArgs.Empty, options.WithDefaults());
    }


    [OutputType]
    public sealed class GetPermissionsSetsResult
    {
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly ImmutableArray<Outputs.GetPermissionsSetsPermissionsSetResult> PermissionsSets;

        [OutputConstructor]
        private GetPermissionsSetsResult(
            string id,

            ImmutableArray<Outputs.GetPermissionsSetsPermissionsSetResult> permissionsSets)
        {
            Id = id;
            PermissionsSets = permissionsSets;
        }
    }
}
