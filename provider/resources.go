// Copyright 2016-2018, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aquasec

import (
	"fmt"
	"path/filepath"

	"github.com/aquasecurity/terraform-provider-aquasec/aquasec"
	"github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfbridge"
	shim "github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfshim"
	shimv2 "github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfshim/sdk-v2"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumiverse/pulumi-aquasec/provider/pkg/version"
)

// all of the token components used below.
const (
	// This variable controls the default name of the package in the package
	// registries for nodejs and python:
	mainPkg = "aquasec"
	// modules:
	mainMod = "index" // the aquasec module
)

// preConfigureCallback is called before the providerConfigure function of the underlying provider.
// It should validate that the provider can be configured, and provide actionable errors in the case
// it cannot be. Configuration variables can be read from `vars` using the `stringValue` function -
// for example `stringValue(vars, "accessKey")`.
func preConfigureCallback(vars resource.PropertyMap, c shim.ResourceConfig) error {
	return nil
}

// Provider returns additional overlaid schema and metadata associated with the provider..
func Provider() tfbridge.ProviderInfo {
	// Instantiate the Terraform provider
	p := shimv2.NewProvider(aquasec.Provider(""))

	// Create a Pulumi provider mapping
	prov := tfbridge.ProviderInfo{
		P:    p,
		Name: "aquasec",
		// DisplayName is a way to be able to change the casing of the provider
		// name when being displayed on the Pulumi registry
		DisplayName: "Aquasec",
		// The default publisher for all packages is Pulumi.
		// Change this to your personal name (or a company name) that you
		// would like to be shown in the Pulumi Registry if this package is published
		// there.
		Publisher: "Pulumiverse",
		// LogoURL is optional but useful to help identify your package in the Pulumi Registry
		// if this package is published there.
		//
		// You may host a logo on a domain you control or add an SVG logo for your package
		// in your repository and use the raw content URL for that file as your logo URL.
		LogoURL: "",
		// PluginDownloadURL is an optional URL used to download the Provider
		// for use in Pulumi programs
		// e.g https://github.com/org/pulumi-provider-name/releases/
		PluginDownloadURL: "github://api.github.com/pulumiverse/pulumi-aquasec",
		Description:       "A Pulumi package for creating and managing Aquasec cloud resources.",
		// category/cloud tag helps with categorizing the package in the Pulumi Registry.
		// For all available categories, see `Keywords` in
		// https://www.pulumi.com/docs/guides/pulumi-packages/schema/#package.
		Keywords:   []string{"pulumi", "aquasec", "category/utility"},
		License:    "Apache-2.0",
		Homepage:   "https://www.pulumi.com",
		Repository: "https://github.com/pulumiverse/pulumi-aquasec",
		// The GitHub Org for the provider - defaults to `terraform-providers`. Note that this
		// should match the TF provider module's require directive, not any replace directives.
		GitHubOrg: "aquasecurity",
		Config:    map[string]*tfbridge.SchemaInfo{
			// Add any required configuration here, or remove the example below if
			// no additional points are required.
			// "region": {
			// 	Type: tfbridge.MakeType("region", "Region"),
			// 	Default: &tfbridge.DefaultInfo{
			// 		EnvVars: []string{"AWS_REGION", "AWS_DEFAULT_REGION"},
			// 	},
			// },
		},
		PreConfigureCallback: preConfigureCallback,
		Resources: map[string]*tfbridge.ResourceInfo{
			// Map each resource in the Terraform provider to a Pulumi type. Two examples
			// are below - the single line form is the common case. The multi-line form is
			// needed only if you wish to override types or other default options.
			//
			// "aws_iam_role": {Tok: tfbridge.MakeResource(mainPkg, mainMod, "IamRole")}
			//
			// "aws_acm_certificate": {
			// 	Tok: tfbridge.MakeResource(mainPkg, mainMod, "Certificate"),
			// 	Fields: map[string]*tfbridge.SchemaInfo{
			// 		"tags": {Type: tfbridge.MakeType(mainPkg, "Tags")},
			// 	},
			// },
			"aquasec_application_scope":           {Tok: tfbridge.MakeResource(mainPkg, mainMod, "ApplicationScope")},
			"aquasec_container_runtime_policy":    {Tok: tfbridge.MakeResource(mainPkg, mainMod, "ContainerRuntimePolicy")},
			"aquasec_enforcer_groups":             {Tok: tfbridge.MakeResource(mainPkg, mainMod, "EnforcerGroups")},
			"aquasec_firewall_policy":             {Tok: tfbridge.MakeResource(mainPkg, mainMod, "FirewallPolicy")},
			"aquasec_function_assurance_policy":   {Tok: tfbridge.MakeResource(mainPkg, mainMod, "FunctionAssurancePolicy")},
			"aquasec_function_runtime_policy":     {Tok: tfbridge.MakeResource(mainPkg, mainMod, "FunctionRuntimePolicy")},
			"aquasec_group":                       {Tok: tfbridge.MakeResource(mainPkg, mainMod, "Group")},
			"aquasec_host_assurance_policy":       {Tok: tfbridge.MakeResource(mainPkg, mainMod, "HostAssurancePolicy")},
			"aquasec_host_runtime_policy":         {Tok: tfbridge.MakeResource(mainPkg, mainMod, "HostRuntimePolicy")},
			"aquasec_image":                       {Tok: tfbridge.MakeResource(mainPkg, mainMod, "Image")},
			"aquasec_image_assurance_policy":      {Tok: tfbridge.MakeResource(mainPkg, mainMod, "ImageAssurancePolicy")},
			"aquasec_integration_registry":        {Tok: tfbridge.MakeResource(mainPkg, mainMod, "IntegrationRegistry")},
			"aquasec_kubernetes_assurance_policy": {Tok: tfbridge.MakeResource(mainPkg, mainMod, "KubernetesAssurancePolicy")},
			"aquasec_notification_slack":          {Tok: tfbridge.MakeResource(mainPkg, mainMod, "NotificationSlack")},
			"aquasec_permissions_sets":            {Tok: tfbridge.MakeResource(mainPkg, mainMod, "PermissionsSets")},
			"aquasec_role":                        {Tok: tfbridge.MakeResource(mainPkg, mainMod, "Role")},
			"aquasec_role_mapping":                {Tok: tfbridge.MakeResource(mainPkg, mainMod, "RoleMapping")},
			"aquasec_role_mapping_saas":           {Tok: tfbridge.MakeResource(mainPkg, mainMod, "RoleMappingSaas")},
			"aquasec_service":                     {Tok: tfbridge.MakeResource(mainPkg, mainMod, "Service")},
			"aquasec_user":                        {Tok: tfbridge.MakeResource(mainPkg, mainMod, "User")},
			"aquasec_user_saas":                   {Tok: tfbridge.MakeResource(mainPkg, mainMod, "UserSaas")},
		},
		DataSources: map[string]*tfbridge.DataSourceInfo{
			// Map each resource in the Terraform provider to a Pulumi function. An example
			// is below.
			// "aws_ami": {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getAmi")},
			"aquasec_application_scope":        {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getApplicationScope")},
			"aquasec_container_runtime_policy": {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getContainerRuntimePolicy")},
			"aquasec_enforcer_groups":          {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getEnforcerGroups")},
			"aquasec_firewall_policy":          {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getFirewallPolicy")},
			"aquasec_function_assurance_policy": {
				Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getFunctionAssurancePolicy"),
			},
			"aquasec_function_runtime_policy": {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getFunctionRuntimePolicy")},
			"aquasec_gateways":                {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getGateways")},
			"aquasec_groups":                  {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getGroups")},
			"aquasec_host_assurance_policy":   {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getHostAssurancePolicy")},
			"aquasec_host_runtime_policy":     {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getHostRuntimePolicy")},
			"aquasec_image":                   {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getImage")},
			"aquasec_image_assurance_policy": {
				Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getImageAssurancePolicy"),
			},
			"aquasec_integration_registries": {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getIntegrationRegistry")},
			"aquasec_integration_state":      {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getIntegrationState")},
			"aquasec_kubernetes_assurance_policy": {
				Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getKubernetesAssurancePolicy"),
			},
			"aquasec_permissions_sets":   {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getPermissionsSets")},
			"aquasec_roles":              {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getRoles")},
			"aquasec_roles_mapping":      {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getRolesMapping")},
			"aquasec_roles_mapping_saas": {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getRolesMappingSaas")},
			"aquasec_service":            {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getService")},
			"aquasec_users":              {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getUsers")},
			"aquasec_users_saas":         {Tok: tfbridge.MakeDataSource(mainPkg, mainMod, "getUsersSaas")},
		},
		JavaScript: &tfbridge.JavaScriptInfo{
			PackageName: "@pulumiverse/aquasec",
			// List any npm dependencies and their versions
			Dependencies: map[string]string{
				"@pulumi/pulumi": "^3.0.0",
			},
			DevDependencies: map[string]string{
				"@types/node": "^10.0.0", // so we can access strongly typed node definitions.
				"@types/mime": "^2.0.0",
			},
			// See the documentation for tfbridge.OverlayInfo for how to lay out this
			// section, or refer to the AWS provider. Delete this section if there are
			// no overlay files.
			//Overlay: &tfbridge.OverlayInfo{},
		},
		Python: &tfbridge.PythonInfo{
			PackageName: "pulumiverse_aquasec",
			// List any Python dependencies and their version ranges
			Requires: map[string]string{
				"pulumi": ">=3.0.0,<4.0.0",
			},
		},
		Golang: &tfbridge.GolangInfo{
			ImportBasePath: filepath.Join(
				fmt.Sprintf("github.com/pulumiverse/pulumi-%[1]s/sdk/", mainPkg),
				tfbridge.GetModuleMajorVersion(version.Version),
				"go",
				mainPkg,
			),
			GenerateResourceContainerTypes: true,
		},
		CSharp: &tfbridge.CSharpInfo{
			RootNamespace: "Pulumiverse",
			PackageReferences: map[string]string{
				"Pulumi": "3.*",
			},
		},
		Java: &tfbridge.JavaInfo{
			BasePackage: "com.pulumiverse",
		},
	}

	prov.SetAutonaming(255, "-")

	return prov
}
