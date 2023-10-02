// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package config

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
	"github.com/pulumiverse/pulumi-aquasec/sdk/go/aquasec/internal"
)

var _ = internal.GetEnvOrDefault

// This is the base URL of your Aqua instance. Can alternatively be sourced from the `AQUA_URL` environment variable.
func GetAquaUrl(ctx *pulumi.Context) string {
	return config.Get(ctx, "aquasec:aquaUrl")
}

// This is the file path for server CA certificates if they are not available on the host OS. Can alternatively be sourced
// from the `AQUA_CA_CERT_PATH` environment variable.
func GetCaCertificatePath(ctx *pulumi.Context) string {
	return config.Get(ctx, "aquasec:caCertificatePath")
}

// This is the file path for Aqua provider configuration. The default configuration path is `~/.aqua/tf.config`. Can
// alternatively be sourced from the `AQUA_CONFIG` environment variable.
func GetConfigPath(ctx *pulumi.Context) string {
	return config.Get(ctx, "aquasec:configPath")
}

// This is the password that should be used to make the connection. Can alternatively be sourced from the `AQUA_PASSWORD`
// environment variable.
func GetPassword(ctx *pulumi.Context) string {
	return config.Get(ctx, "aquasec:password")
}

// This is the user id that should be used to make the connection. Can alternatively be sourced from the `AQUA_USER`
// environment variable.
func GetUsername(ctx *pulumi.Context) string {
	return config.Get(ctx, "aquasec:username")
}

// If true, server tls certificates will be verified by the client before making a connection. Defaults to true. Can
// alternatively be sourced from the `AQUA_TLS_VERIFY` environment variable.
func GetVerifyTls(ctx *pulumi.Context) bool {
	return config.GetBool(ctx, "aquasec:verifyTls")
}
