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
    [AquasecResourceType("aquasec:index/integrationRegistry:IntegrationRegistry")]
    public partial class IntegrationRegistry : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The username of the user who created or last modified the registry
        /// </summary>
        [Output("author")]
        public Output<string> Author { get; private set; } = null!;

        /// <summary>
        /// Whether to automatically pull images from the registry on creation and daily
        /// </summary>
        [Output("autoPull")]
        public Output<bool?> AutoPull { get; private set; } = null!;

        /// <summary>
        /// The interval in days to start pulling new images from the registry, Defaults to 1
        /// </summary>
        [Output("autoPullInterval")]
        public Output<int?> AutoPullInterval { get; private set; } = null!;

        /// <summary>
        /// Maximum number of repositories to pull every day, defaults to 100
        /// </summary>
        [Output("autoPullMax")]
        public Output<int?> AutoPullMax { get; private set; } = null!;

        /// <summary>
        /// Whether to automatically pull and rescan images from the registry on creation and daily
        /// </summary>
        [Output("autoPullRescan")]
        public Output<bool?> AutoPullRescan { get; private set; } = null!;

        /// <summary>
        /// The time of day to start pulling new images from the registry, in the format HH:MM (24-hour clock), defaults to 03:00
        /// </summary>
        [Output("autoPullTime")]
        public Output<string?> AutoPullTime { get; private set; } = null!;

        /// <summary>
        /// Additional condition for pulling and rescanning images, Defaults to 'none'
        /// </summary>
        [Output("imageCreationDateCondition")]
        public Output<string> ImageCreationDateCondition { get; private set; } = null!;

        /// <summary>
        /// The last time the registry was modified in UNIX time
        /// </summary>
        [Output("lastUpdated")]
        public Output<string> LastUpdated { get; private set; } = null!;

        /// <summary>
        /// The name of the registry; string, required - this will be treated as the registry's ID, so choose a simple alphanumerical name without special signs and spaces
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        [Output("options")]
        public Output<ImmutableArray<Outputs.IntegrationRegistryOption>> Options { get; private set; } = null!;

        /// <summary>
        /// The password for registry authentication
        /// </summary>
        [Output("password")]
        public Output<string?> Password { get; private set; } = null!;

        /// <summary>
        /// List of possible prefixes to image names pulled from the registry
        /// </summary>
        [Output("prefixes")]
        public Output<ImmutableArray<string>> Prefixes { get; private set; } = null!;

        /// <summary>
        /// When auto pull image enabled, sets maximum age of auto pulled images (for example for 5 Days the value should be: 5D), Requires `image_creation_date_condition = "image_age"`
        /// </summary>
        [Output("pullImageAge")]
        public Output<string> PullImageAge { get; private set; } = null!;

        /// <summary>
        /// When auto pull image enabled, sets maximum age of auto pulled images tags from each repository (based on image creation date) Requires `image_creation_date_condition = "image_count"`
        /// </summary>
        [Output("pullImageCount")]
        public Output<int> PullImageCount { get; private set; } = null!;

        /// <summary>
        /// List of scanner names
        /// </summary>
        [Output("scannerNames")]
        public Output<ImmutableArray<string>> ScannerNames { get; private set; } = null!;

        /// <summary>
        /// The Scanner type
        /// </summary>
        [Output("scannerType")]
        public Output<string> ScannerType { get; private set; } = null!;

        /// <summary>
        /// Registry type (HUB / V1 / V2 / ENGINE / AWS / GCR).
        /// </summary>
        [Output("type")]
        public Output<string> Type { get; private set; } = null!;

        /// <summary>
        /// The URL, address or region of the registry
        /// </summary>
        [Output("url")]
        public Output<string> Url { get; private set; } = null!;

        /// <summary>
        /// The username for registry authentication.
        /// </summary>
        [Output("username")]
        public Output<string?> Username { get; private set; } = null!;


        /// <summary>
        /// Create a IntegrationRegistry resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public IntegrationRegistry(string name, IntegrationRegistryArgs args, CustomResourceOptions? options = null)
            : base("aquasec:index/integrationRegistry:IntegrationRegistry", name, args ?? new IntegrationRegistryArgs(), MakeResourceOptions(options, ""))
        {
        }

        private IntegrationRegistry(string name, Input<string> id, IntegrationRegistryState? state = null, CustomResourceOptions? options = null)
            : base("aquasec:index/integrationRegistry:IntegrationRegistry", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
                PluginDownloadURL = "github://api.github.com/pulumiverse/pulumi-aquasec",
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing IntegrationRegistry resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static IntegrationRegistry Get(string name, Input<string> id, IntegrationRegistryState? state = null, CustomResourceOptions? options = null)
        {
            return new IntegrationRegistry(name, id, state, options);
        }
    }

    public sealed class IntegrationRegistryArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The username of the user who created or last modified the registry
        /// </summary>
        [Input("author")]
        public Input<string>? Author { get; set; }

        /// <summary>
        /// Whether to automatically pull images from the registry on creation and daily
        /// </summary>
        [Input("autoPull")]
        public Input<bool>? AutoPull { get; set; }

        /// <summary>
        /// The interval in days to start pulling new images from the registry, Defaults to 1
        /// </summary>
        [Input("autoPullInterval")]
        public Input<int>? AutoPullInterval { get; set; }

        /// <summary>
        /// Maximum number of repositories to pull every day, defaults to 100
        /// </summary>
        [Input("autoPullMax")]
        public Input<int>? AutoPullMax { get; set; }

        /// <summary>
        /// Whether to automatically pull and rescan images from the registry on creation and daily
        /// </summary>
        [Input("autoPullRescan")]
        public Input<bool>? AutoPullRescan { get; set; }

        /// <summary>
        /// The time of day to start pulling new images from the registry, in the format HH:MM (24-hour clock), defaults to 03:00
        /// </summary>
        [Input("autoPullTime")]
        public Input<string>? AutoPullTime { get; set; }

        /// <summary>
        /// Additional condition for pulling and rescanning images, Defaults to 'none'
        /// </summary>
        [Input("imageCreationDateCondition")]
        public Input<string>? ImageCreationDateCondition { get; set; }

        /// <summary>
        /// The last time the registry was modified in UNIX time
        /// </summary>
        [Input("lastUpdated")]
        public Input<string>? LastUpdated { get; set; }

        /// <summary>
        /// The name of the registry; string, required - this will be treated as the registry's ID, so choose a simple alphanumerical name without special signs and spaces
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        [Input("options")]
        private InputList<Inputs.IntegrationRegistryOptionArgs>? _options;
        public InputList<Inputs.IntegrationRegistryOptionArgs> Options
        {
            get => _options ?? (_options = new InputList<Inputs.IntegrationRegistryOptionArgs>());
            set => _options = value;
        }

        /// <summary>
        /// The password for registry authentication
        /// </summary>
        [Input("password")]
        public Input<string>? Password { get; set; }

        [Input("prefixes")]
        private InputList<string>? _prefixes;

        /// <summary>
        /// List of possible prefixes to image names pulled from the registry
        /// </summary>
        public InputList<string> Prefixes
        {
            get => _prefixes ?? (_prefixes = new InputList<string>());
            set => _prefixes = value;
        }

        /// <summary>
        /// When auto pull image enabled, sets maximum age of auto pulled images (for example for 5 Days the value should be: 5D), Requires `image_creation_date_condition = "image_age"`
        /// </summary>
        [Input("pullImageAge")]
        public Input<string>? PullImageAge { get; set; }

        /// <summary>
        /// When auto pull image enabled, sets maximum age of auto pulled images tags from each repository (based on image creation date) Requires `image_creation_date_condition = "image_count"`
        /// </summary>
        [Input("pullImageCount")]
        public Input<int>? PullImageCount { get; set; }

        [Input("scannerNames")]
        private InputList<string>? _scannerNames;

        /// <summary>
        /// List of scanner names
        /// </summary>
        public InputList<string> ScannerNames
        {
            get => _scannerNames ?? (_scannerNames = new InputList<string>());
            set => _scannerNames = value;
        }

        /// <summary>
        /// The Scanner type
        /// </summary>
        [Input("scannerType")]
        public Input<string>? ScannerType { get; set; }

        /// <summary>
        /// Registry type (HUB / V1 / V2 / ENGINE / AWS / GCR).
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        /// <summary>
        /// The URL, address or region of the registry
        /// </summary>
        [Input("url")]
        public Input<string>? Url { get; set; }

        /// <summary>
        /// The username for registry authentication.
        /// </summary>
        [Input("username")]
        public Input<string>? Username { get; set; }

        public IntegrationRegistryArgs()
        {
        }
        public static new IntegrationRegistryArgs Empty => new IntegrationRegistryArgs();
    }

    public sealed class IntegrationRegistryState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The username of the user who created or last modified the registry
        /// </summary>
        [Input("author")]
        public Input<string>? Author { get; set; }

        /// <summary>
        /// Whether to automatically pull images from the registry on creation and daily
        /// </summary>
        [Input("autoPull")]
        public Input<bool>? AutoPull { get; set; }

        /// <summary>
        /// The interval in days to start pulling new images from the registry, Defaults to 1
        /// </summary>
        [Input("autoPullInterval")]
        public Input<int>? AutoPullInterval { get; set; }

        /// <summary>
        /// Maximum number of repositories to pull every day, defaults to 100
        /// </summary>
        [Input("autoPullMax")]
        public Input<int>? AutoPullMax { get; set; }

        /// <summary>
        /// Whether to automatically pull and rescan images from the registry on creation and daily
        /// </summary>
        [Input("autoPullRescan")]
        public Input<bool>? AutoPullRescan { get; set; }

        /// <summary>
        /// The time of day to start pulling new images from the registry, in the format HH:MM (24-hour clock), defaults to 03:00
        /// </summary>
        [Input("autoPullTime")]
        public Input<string>? AutoPullTime { get; set; }

        /// <summary>
        /// Additional condition for pulling and rescanning images, Defaults to 'none'
        /// </summary>
        [Input("imageCreationDateCondition")]
        public Input<string>? ImageCreationDateCondition { get; set; }

        /// <summary>
        /// The last time the registry was modified in UNIX time
        /// </summary>
        [Input("lastUpdated")]
        public Input<string>? LastUpdated { get; set; }

        /// <summary>
        /// The name of the registry; string, required - this will be treated as the registry's ID, so choose a simple alphanumerical name without special signs and spaces
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        [Input("options")]
        private InputList<Inputs.IntegrationRegistryOptionGetArgs>? _options;
        public InputList<Inputs.IntegrationRegistryOptionGetArgs> Options
        {
            get => _options ?? (_options = new InputList<Inputs.IntegrationRegistryOptionGetArgs>());
            set => _options = value;
        }

        /// <summary>
        /// The password for registry authentication
        /// </summary>
        [Input("password")]
        public Input<string>? Password { get; set; }

        [Input("prefixes")]
        private InputList<string>? _prefixes;

        /// <summary>
        /// List of possible prefixes to image names pulled from the registry
        /// </summary>
        public InputList<string> Prefixes
        {
            get => _prefixes ?? (_prefixes = new InputList<string>());
            set => _prefixes = value;
        }

        /// <summary>
        /// When auto pull image enabled, sets maximum age of auto pulled images (for example for 5 Days the value should be: 5D), Requires `image_creation_date_condition = "image_age"`
        /// </summary>
        [Input("pullImageAge")]
        public Input<string>? PullImageAge { get; set; }

        /// <summary>
        /// When auto pull image enabled, sets maximum age of auto pulled images tags from each repository (based on image creation date) Requires `image_creation_date_condition = "image_count"`
        /// </summary>
        [Input("pullImageCount")]
        public Input<int>? PullImageCount { get; set; }

        [Input("scannerNames")]
        private InputList<string>? _scannerNames;

        /// <summary>
        /// List of scanner names
        /// </summary>
        public InputList<string> ScannerNames
        {
            get => _scannerNames ?? (_scannerNames = new InputList<string>());
            set => _scannerNames = value;
        }

        /// <summary>
        /// The Scanner type
        /// </summary>
        [Input("scannerType")]
        public Input<string>? ScannerType { get; set; }

        /// <summary>
        /// Registry type (HUB / V1 / V2 / ENGINE / AWS / GCR).
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        /// <summary>
        /// The URL, address or region of the registry
        /// </summary>
        [Input("url")]
        public Input<string>? Url { get; set; }

        /// <summary>
        /// The username for registry authentication.
        /// </summary>
        [Input("username")]
        public Input<string>? Username { get; set; }

        public IntegrationRegistryState()
        {
        }
        public static new IntegrationRegistryState Empty => new IntegrationRegistryState();
    }
}
