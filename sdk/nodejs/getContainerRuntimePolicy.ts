// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

/**
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as aquasec from "@pulumi/aquasec";
 *
 * const containerRuntimePolicy = aquasec.getContainerRuntimePolicy({
 *     name: "FunctionRuntimePolicyName",
 * });
 * export const containerRuntimePolicyDetails = containerRuntimePolicy;
 * ```
 */
export function getContainerRuntimePolicy(args: GetContainerRuntimePolicyArgs, opts?: pulumi.InvokeOptions): Promise<GetContainerRuntimePolicyResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("aquasec:index/getContainerRuntimePolicy:getContainerRuntimePolicy", {
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getContainerRuntimePolicy.
 */
export interface GetContainerRuntimePolicyArgs {
    /**
     * Name of the container runtime policy
     */
    name: string;
}

/**
 * A collection of values returned by getContainerRuntimePolicy.
 */
export interface GetContainerRuntimePolicyResult {
    /**
     * List of executables that are allowed for the user.
     */
    readonly allowedExecutables: string[];
    /**
     * List of registries that allowed for running containers.
     */
    readonly allowedRegistries: string[];
    /**
     * Indicates the application scope of the service.
     */
    readonly applicationScopes: string[];
    /**
     * If true, all network activity will be audited.
     */
    readonly auditAllNetworkActivity: boolean;
    /**
     * If true, all process activity will be audited.
     */
    readonly auditAllProcessesActivity: boolean;
    /**
     * If true, full command arguments will be audited.
     */
    readonly auditFullCommandArguments: boolean;
    /**
     * Username of the account that created the service.
     */
    readonly author: string;
    /**
     * If true, prevent containers from running with access to host network.
     */
    readonly blockAccessHostNetwork: boolean;
    /**
     * If true, prevent containers from running with adding capabilities with `--cap-add` privilege.
     */
    readonly blockAddingCapabilities: boolean;
    /**
     * If true, exec into a container is prevented.
     */
    readonly blockContainerExec: boolean;
    /**
     * Detect and prevent communication to DNS/IP addresses known to be used for Cryptocurrency Mining
     */
    readonly blockCryptocurrencyMining: boolean;
    /**
     * Detect and prevent running in-memory execution
     */
    readonly blockFilelessExec: boolean;
    /**
     * If true, prevent containers from running with the capability to bind in port lower than 1024.
     */
    readonly blockLowPortBinding: boolean;
    /**
     * If true, running non-compliant image in the container is prevented.
     */
    readonly blockNonCompliantImages: boolean;
    /**
     * If true, running containers in non-compliant pods is prevented.
     */
    readonly blockNonCompliantWorkloads: boolean;
    /**
     * If true, running non-kubernetes containers is prevented.
     */
    readonly blockNonK8sContainers: boolean;
    /**
     * If true, prevent containers from running with privileged container capability.
     */
    readonly blockPrivilegedContainers: boolean;
    /**
     * If true, reverse shell is prevented.
     */
    readonly blockReverseShell: boolean;
    /**
     * If true, prevent containers from running with root user.
     */
    readonly blockRootUser: boolean;
    /**
     * If true, running images in the container that are not registered in Aqua is prevented.
     */
    readonly blockUnregisteredImages: boolean;
    /**
     * If true, prevent containers from running with the privilege to use the IPC namespace.
     */
    readonly blockUseIpcNamespace: boolean;
    /**
     * If true, prevent containers from running with the privilege to use the PID namespace.
     */
    readonly blockUsePidNamespace: boolean;
    /**
     * If true, prevent containers from running with the privilege to use the user namespace.
     */
    readonly blockUseUserNamespace: boolean;
    /**
     * If true, prevent containers from running with the privilege to use the UTS namespace.
     */
    readonly blockUseUtsNamespace: boolean;
    /**
     * If true, prevents containers from using specific Unix capabilities.
     */
    readonly blockedCapabilities: string[];
    /**
     * List of executables that are prevented from running in containers.
     */
    readonly blockedExecutables: string[];
    /**
     * List of files that are prevented from being read, modified and executed in the containers.
     */
    readonly blockedFiles: string[];
    /**
     * List of blocked inbound ports.
     */
    readonly blockedInboundPorts: string[];
    /**
     * List of blocked outbound ports.
     */
    readonly blockedOutboundPorts: string[];
    /**
     * Prevent containers from reading, writing, or executing all files in the list of packages.
     */
    readonly blockedPackages: string[];
    /**
     * List of volumes that are prevented from being mounted in the containers.
     */
    readonly blockedVolumes: string[];
    /**
     * List of processes that will be allowed.
     */
    readonly containerExecAllowedProcesses: string[];
    /**
     * The description of the container runtime policy
     */
    readonly description: string;
    /**
     * If true, executables that are not in the original image is prevented from running.
     */
    readonly enableDriftPrevention: boolean;
    /**
     * If true, fork bombs are prevented in the containers.
     */
    readonly enableForkGuard: boolean;
    /**
     * If true, detect and prevent communication from containers to IP addresses known to have a bad reputation.
     */
    readonly enableIpReputationSecurity: boolean;
    /**
     * If true, detects port scanning behavior in the container.
     */
    readonly enablePortScanDetection: boolean;
    /**
     * Indicates if the runtime policy is enabled or not.
     */
    readonly enabled: boolean;
    /**
     * Indicates that policy should effect container execution (not just for audit).
     */
    readonly enforce: boolean;
    /**
     * Indicates the number of days after which the runtime policy will be changed to enforce mode.
     */
    readonly enforceAfterDays: number;
    /**
     * List of files and directories to be excluded from the read-only list.
     */
    readonly exceptionalReadonlyFilesAndDirectories: string[];
    /**
     * Configuration for file integrity monitoring.
     */
    readonly fileIntegrityMonitorings: outputs.GetContainerRuntimePolicyFileIntegrityMonitoring[];
    /**
     * Process limit for the fork guard.
     */
    readonly forkGuardProcessLimit: number;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * If true, prevents the container from obtaining new privileges at runtime. (only enabled in enforce mode)
     */
    readonly limitNewPrivileges: boolean;
    /**
     * If true, system time changes will be monitored.
     */
    readonly monitorSystemTimeChanges: boolean;
    /**
     * Name of the container runtime policy
     */
    readonly name: string;
    /**
     * List of files and directories to be restricted as read-only
     */
    readonly readonlyFilesAndDirectories: string[];
    /**
     * List of IPs/ CIDRs that will be allowed
     */
    readonly reverseShellAllowedIps: string[];
    /**
     * List of processes that will be allowed
     */
    readonly reverseShellAllowedProcesses: string[];
    /**
     * Logical expression of how to compute the dependency of the scope variables.
     */
    readonly scopeExpression: string;
    /**
     * List of scope attributes.
     */
    readonly scopeVariables: outputs.GetContainerRuntimePolicyScopeVariable[];
}

export function getContainerRuntimePolicyOutput(args: GetContainerRuntimePolicyOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetContainerRuntimePolicyResult> {
    return pulumi.output(args).apply(a => getContainerRuntimePolicy(a, opts))
}

/**
 * A collection of arguments for invoking getContainerRuntimePolicy.
 */
export interface GetContainerRuntimePolicyOutputArgs {
    /**
     * Name of the container runtime policy
     */
    name: pulumi.Input<string>;
}
