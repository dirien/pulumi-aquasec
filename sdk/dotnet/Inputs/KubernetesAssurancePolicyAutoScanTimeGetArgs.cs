// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;
using Pulumi;

namespace Pulumiverse.Aquasec.Inputs
{

    public sealed class KubernetesAssurancePolicyAutoScanTimeGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("iteration")]
        public Input<int>? Iteration { get; set; }

        [Input("iterationType")]
        public Input<string>? IterationType { get; set; }

        [Input("time")]
        public Input<string>? Time { get; set; }

        [Input("weekDays")]
        private InputList<string>? _weekDays;
        public InputList<string> WeekDays
        {
            get => _weekDays ?? (_weekDays = new InputList<string>());
            set => _weekDays = value;
        }

        public KubernetesAssurancePolicyAutoScanTimeGetArgs()
        {
        }
        public static new KubernetesAssurancePolicyAutoScanTimeGetArgs Empty => new KubernetesAssurancePolicyAutoScanTimeGetArgs();
    }
}
