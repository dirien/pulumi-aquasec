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
 * const containerRuntimePolicy = new aquasec.ContainerRuntimePolicy("container_runtime_policy", {
 *     allowedExecutables: [
 *         "exe",
 *         "bin",
 *     ],
 *     allowedRegistries: [
 *         "registry1",
 *         "registry2",
 *     ],
 *     auditAllNetworkActivity: true,
 *     auditAllProcessesActivity: true,
 *     auditFullCommandArguments: true,
 *     blockAccessHostNetwork: true,
 *     blockAddingCapabilities: true,
 *     blockContainerExec: true,
 *     blockCryptocurrencyMining: true,
 *     blockFilelessExec: true,
 *     blockLowPortBinding: true,
 *     blockNonCompliantImages: true,
 *     blockNonCompliantWorkloads: true,
 *     blockNonK8sContainers: true,
 *     blockPrivilegedContainers: true,
 *     blockReverseShell: true,
 *     blockRootUser: true,
 *     blockUnregisteredImages: true,
 *     blockUseIpcNamespace: true,
 *     blockUsePidNamespace: true,
 *     blockUseUserNamespace: true,
 *     blockUseUtsNamespace: true,
 *     blockedCapabilities: [
 *         "AUDIT_CONTROL",
 *         "AUDIT_WRITE",
 *     ],
 *     blockedExecutables: [
 *         "exe1",
 *         "exe2",
 *     ],
 *     blockedFiles: [
 *         "test1",
 *         "test2",
 *     ],
 *     blockedInboundPorts: [
 *         "80",
 *         "8080",
 *     ],
 *     blockedOutboundPorts: [
 *         "90",
 *         "9090",
 *     ],
 *     blockedPackages: [
 *         "pkg",
 *         "pkg2",
 *     ],
 *     blockedVolumes: [
 *         "blocked",
 *         "vol",
 *     ],
 *     containerExecAllowedProcesses: [
 *         "proc1",
 *         "proc2",
 *     ],
 *     description: "container_runtime_policy",
 *     enableDriftPrevention: true,
 *     enableForkGuard: true,
 *     enableIpReputationSecurity: true,
 *     enablePortScanDetection: true,
 *     enabled: true,
 *     enforce: false,
 *     exceptionalReadonlyFilesAndDirectories: [
 *         "readonly2",
 *         "/dir2/",
 *     ],
 *     fileIntegrityMonitoring: {
 *         excludedPaths: ["expaths"],
 *         excludedProcesses: ["exprocess"],
 *         excludedUsers: ["expuser"],
 *         monitorAttributes: true,
 *         monitorCreate: true,
 *         monitorDelete: true,
 *         monitorModify: true,
 *         monitorRead: true,
 *         monitoredPaths: ["paths"],
 *         monitoredProcesses: ["process"],
 *         monitoredUsers: ["user"],
 *     },
 *     forkGuardProcessLimit: 13,
 *     limitNewPrivileges: true,
 *     monitorSystemTimeChanges: true,
 *     readonlyFilesAndDirectories: [
 *         "readonly",
 *         "/dir/",
 *     ],
 *     reverseShellAllowedIps: [
 *         "ip1",
 *         "ip2",
 *     ],
 *     reverseShellAllowedProcesses: [
 *         "proc1",
 *         "proc2",
 *     ],
 * });
 * ```
 */
export class ContainerRuntimePolicy extends pulumi.CustomResource {
    /**
     * Get an existing ContainerRuntimePolicy resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ContainerRuntimePolicyState, opts?: pulumi.CustomResourceOptions): ContainerRuntimePolicy {
        return new ContainerRuntimePolicy(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'aquasec:index/containerRuntimePolicy:ContainerRuntimePolicy';

    /**
     * Returns true if the given object is an instance of ContainerRuntimePolicy.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ContainerRuntimePolicy {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ContainerRuntimePolicy.__pulumiType;
    }

    /**
     * List of executables that are allowed for the user.
     */
    public readonly allowedExecutables!: pulumi.Output<string[] | undefined>;
    /**
     * List of registries that allowed for running containers.
     */
    public readonly allowedRegistries!: pulumi.Output<string[] | undefined>;
    /**
     * Indicates the application scope of the service.
     */
    public readonly applicationScopes!: pulumi.Output<string[]>;
    /**
     * If true, all network activity will be audited.
     */
    public readonly auditAllNetworkActivity!: pulumi.Output<boolean | undefined>;
    /**
     * If true, all process activity will be audited.
     */
    public readonly auditAllProcessesActivity!: pulumi.Output<boolean | undefined>;
    /**
     * If true, full command arguments will be audited.
     */
    public readonly auditFullCommandArguments!: pulumi.Output<boolean | undefined>;
    /**
     * Username of the account that created the service.
     */
    public /*out*/ readonly author!: pulumi.Output<string>;
    /**
     * If true, prevent containers from running with access to host network.
     */
    public readonly blockAccessHostNetwork!: pulumi.Output<boolean | undefined>;
    /**
     * If true, prevent containers from running with adding capabilities with `--cap-add` privilege.
     */
    public readonly blockAddingCapabilities!: pulumi.Output<boolean | undefined>;
    /**
     * If true, exec into a container is prevented.
     */
    public readonly blockContainerExec!: pulumi.Output<boolean | undefined>;
    /**
     * Detect and prevent communication to DNS/IP addresses known to be used for Cryptocurrency Mining
     */
    public readonly blockCryptocurrencyMining!: pulumi.Output<boolean | undefined>;
    /**
     * Detect and prevent running in-memory execution
     */
    public readonly blockFilelessExec!: pulumi.Output<boolean | undefined>;
    /**
     * If true, prevent containers from running with the capability to bind in port lower than 1024.
     */
    public readonly blockLowPortBinding!: pulumi.Output<boolean | undefined>;
    /**
     * If true, running non-compliant image in the container is prevented.
     */
    public readonly blockNonCompliantImages!: pulumi.Output<boolean | undefined>;
    /**
     * If true, running containers in non-compliant pods is prevented.
     */
    public readonly blockNonCompliantWorkloads!: pulumi.Output<boolean | undefined>;
    /**
     * If true, running non-kubernetes containers is prevented.
     */
    public readonly blockNonK8sContainers!: pulumi.Output<boolean | undefined>;
    /**
     * If true, prevent containers from running with privileged container capability.
     */
    public readonly blockPrivilegedContainers!: pulumi.Output<boolean | undefined>;
    /**
     * If true, reverse shell is prevented.
     */
    public readonly blockReverseShell!: pulumi.Output<boolean | undefined>;
    /**
     * If true, prevent containers from running with root user.
     */
    public readonly blockRootUser!: pulumi.Output<boolean | undefined>;
    /**
     * If true, running images in the container that are not registered in Aqua is prevented.
     */
    public readonly blockUnregisteredImages!: pulumi.Output<boolean | undefined>;
    /**
     * If true, prevent containers from running with the privilege to use the IPC namespace.
     */
    public readonly blockUseIpcNamespace!: pulumi.Output<boolean | undefined>;
    /**
     * If true, prevent containers from running with the privilege to use the PID namespace.
     */
    public readonly blockUsePidNamespace!: pulumi.Output<boolean | undefined>;
    /**
     * If true, prevent containers from running with the privilege to use the user namespace.
     */
    public readonly blockUseUserNamespace!: pulumi.Output<boolean | undefined>;
    /**
     * If true, prevent containers from running with the privilege to use the UTS namespace.
     */
    public readonly blockUseUtsNamespace!: pulumi.Output<boolean | undefined>;
    /**
     * If true, prevents containers from using specific Unix capabilities.
     */
    public readonly blockedCapabilities!: pulumi.Output<string[] | undefined>;
    /**
     * List of executables that are prevented from running in containers.
     */
    public readonly blockedExecutables!: pulumi.Output<string[] | undefined>;
    /**
     * List of files that are prevented from being read, modified and executed in the containers.
     */
    public readonly blockedFiles!: pulumi.Output<string[] | undefined>;
    /**
     * List of blocked inbound ports.
     */
    public readonly blockedInboundPorts!: pulumi.Output<string[] | undefined>;
    /**
     * List of blocked outbound ports.
     */
    public readonly blockedOutboundPorts!: pulumi.Output<string[] | undefined>;
    /**
     * Prevent containers from reading, writing, or executing all files in the list of packages.
     */
    public readonly blockedPackages!: pulumi.Output<string[] | undefined>;
    /**
     * List of volumes that are prevented from being mounted in the containers.
     */
    public readonly blockedVolumes!: pulumi.Output<string[] | undefined>;
    /**
     * List of processes that will be allowed.
     */
    public readonly containerExecAllowedProcesses!: pulumi.Output<string[] | undefined>;
    /**
     * The description of the container runtime policy
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * If true, executables that are not in the original image is prevented from running.
     */
    public readonly enableDriftPrevention!: pulumi.Output<boolean | undefined>;
    /**
     * If true, fork bombs are prevented in the containers.
     */
    public readonly enableForkGuard!: pulumi.Output<boolean | undefined>;
    /**
     * If true, detect and prevent communication from containers to IP addresses known to have a bad reputation.
     */
    public readonly enableIpReputationSecurity!: pulumi.Output<boolean | undefined>;
    /**
     * If true, detects port scanning behavior in the container.
     */
    public readonly enablePortScanDetection!: pulumi.Output<boolean | undefined>;
    /**
     * Indicates if the runtime policy is enabled or not.
     */
    public readonly enabled!: pulumi.Output<boolean | undefined>;
    /**
     * Indicates that policy should effect container execution (not just for audit).
     */
    public readonly enforce!: pulumi.Output<boolean | undefined>;
    /**
     * Indicates the number of days after which the runtime policy will be changed to enforce mode.
     */
    public readonly enforceAfterDays!: pulumi.Output<number | undefined>;
    /**
     * List of files and directories to be excluded from the read-only list.
     */
    public readonly exceptionalReadonlyFilesAndDirectories!: pulumi.Output<string[] | undefined>;
    /**
     * Configuration for file integrity monitoring.
     */
    public readonly fileIntegrityMonitoring!: pulumi.Output<outputs.ContainerRuntimePolicyFileIntegrityMonitoring | undefined>;
    /**
     * Process limit for the fork guard.
     */
    public readonly forkGuardProcessLimit!: pulumi.Output<number | undefined>;
    /**
     * If true, prevents the container from obtaining new privileges at runtime. (only enabled in enforce mode)
     */
    public readonly limitNewPrivileges!: pulumi.Output<boolean | undefined>;
    /**
     * Configuration for Real-Time Malware Protection.
     */
    public readonly malwareScanOptions!: pulumi.Output<outputs.ContainerRuntimePolicyMalwareScanOptions | undefined>;
    /**
     * If true, system time changes will be monitored.
     */
    public readonly monitorSystemTimeChanges!: pulumi.Output<boolean | undefined>;
    /**
     * Name of the container runtime policy
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * List of files and directories to be restricted as read-only
     */
    public readonly readonlyFilesAndDirectories!: pulumi.Output<string[] | undefined>;
    /**
     * List of IPs/ CIDRs that will be allowed
     */
    public readonly reverseShellAllowedIps!: pulumi.Output<string[] | undefined>;
    /**
     * List of processes that will be allowed
     */
    public readonly reverseShellAllowedProcesses!: pulumi.Output<string[] | undefined>;
    /**
     * Logical expression of how to compute the dependency of the scope variables.
     */
    public readonly scopeExpression!: pulumi.Output<string>;
    /**
     * List of scope attributes.
     */
    public readonly scopeVariables!: pulumi.Output<outputs.ContainerRuntimePolicyScopeVariable[]>;

    /**
     * Create a ContainerRuntimePolicy resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: ContainerRuntimePolicyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ContainerRuntimePolicyArgs | ContainerRuntimePolicyState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ContainerRuntimePolicyState | undefined;
            resourceInputs["allowedExecutables"] = state ? state.allowedExecutables : undefined;
            resourceInputs["allowedRegistries"] = state ? state.allowedRegistries : undefined;
            resourceInputs["applicationScopes"] = state ? state.applicationScopes : undefined;
            resourceInputs["auditAllNetworkActivity"] = state ? state.auditAllNetworkActivity : undefined;
            resourceInputs["auditAllProcessesActivity"] = state ? state.auditAllProcessesActivity : undefined;
            resourceInputs["auditFullCommandArguments"] = state ? state.auditFullCommandArguments : undefined;
            resourceInputs["author"] = state ? state.author : undefined;
            resourceInputs["blockAccessHostNetwork"] = state ? state.blockAccessHostNetwork : undefined;
            resourceInputs["blockAddingCapabilities"] = state ? state.blockAddingCapabilities : undefined;
            resourceInputs["blockContainerExec"] = state ? state.blockContainerExec : undefined;
            resourceInputs["blockCryptocurrencyMining"] = state ? state.blockCryptocurrencyMining : undefined;
            resourceInputs["blockFilelessExec"] = state ? state.blockFilelessExec : undefined;
            resourceInputs["blockLowPortBinding"] = state ? state.blockLowPortBinding : undefined;
            resourceInputs["blockNonCompliantImages"] = state ? state.blockNonCompliantImages : undefined;
            resourceInputs["blockNonCompliantWorkloads"] = state ? state.blockNonCompliantWorkloads : undefined;
            resourceInputs["blockNonK8sContainers"] = state ? state.blockNonK8sContainers : undefined;
            resourceInputs["blockPrivilegedContainers"] = state ? state.blockPrivilegedContainers : undefined;
            resourceInputs["blockReverseShell"] = state ? state.blockReverseShell : undefined;
            resourceInputs["blockRootUser"] = state ? state.blockRootUser : undefined;
            resourceInputs["blockUnregisteredImages"] = state ? state.blockUnregisteredImages : undefined;
            resourceInputs["blockUseIpcNamespace"] = state ? state.blockUseIpcNamespace : undefined;
            resourceInputs["blockUsePidNamespace"] = state ? state.blockUsePidNamespace : undefined;
            resourceInputs["blockUseUserNamespace"] = state ? state.blockUseUserNamespace : undefined;
            resourceInputs["blockUseUtsNamespace"] = state ? state.blockUseUtsNamespace : undefined;
            resourceInputs["blockedCapabilities"] = state ? state.blockedCapabilities : undefined;
            resourceInputs["blockedExecutables"] = state ? state.blockedExecutables : undefined;
            resourceInputs["blockedFiles"] = state ? state.blockedFiles : undefined;
            resourceInputs["blockedInboundPorts"] = state ? state.blockedInboundPorts : undefined;
            resourceInputs["blockedOutboundPorts"] = state ? state.blockedOutboundPorts : undefined;
            resourceInputs["blockedPackages"] = state ? state.blockedPackages : undefined;
            resourceInputs["blockedVolumes"] = state ? state.blockedVolumes : undefined;
            resourceInputs["containerExecAllowedProcesses"] = state ? state.containerExecAllowedProcesses : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["enableDriftPrevention"] = state ? state.enableDriftPrevention : undefined;
            resourceInputs["enableForkGuard"] = state ? state.enableForkGuard : undefined;
            resourceInputs["enableIpReputationSecurity"] = state ? state.enableIpReputationSecurity : undefined;
            resourceInputs["enablePortScanDetection"] = state ? state.enablePortScanDetection : undefined;
            resourceInputs["enabled"] = state ? state.enabled : undefined;
            resourceInputs["enforce"] = state ? state.enforce : undefined;
            resourceInputs["enforceAfterDays"] = state ? state.enforceAfterDays : undefined;
            resourceInputs["exceptionalReadonlyFilesAndDirectories"] = state ? state.exceptionalReadonlyFilesAndDirectories : undefined;
            resourceInputs["fileIntegrityMonitoring"] = state ? state.fileIntegrityMonitoring : undefined;
            resourceInputs["forkGuardProcessLimit"] = state ? state.forkGuardProcessLimit : undefined;
            resourceInputs["limitNewPrivileges"] = state ? state.limitNewPrivileges : undefined;
            resourceInputs["malwareScanOptions"] = state ? state.malwareScanOptions : undefined;
            resourceInputs["monitorSystemTimeChanges"] = state ? state.monitorSystemTimeChanges : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["readonlyFilesAndDirectories"] = state ? state.readonlyFilesAndDirectories : undefined;
            resourceInputs["reverseShellAllowedIps"] = state ? state.reverseShellAllowedIps : undefined;
            resourceInputs["reverseShellAllowedProcesses"] = state ? state.reverseShellAllowedProcesses : undefined;
            resourceInputs["scopeExpression"] = state ? state.scopeExpression : undefined;
            resourceInputs["scopeVariables"] = state ? state.scopeVariables : undefined;
        } else {
            const args = argsOrState as ContainerRuntimePolicyArgs | undefined;
            resourceInputs["allowedExecutables"] = args ? args.allowedExecutables : undefined;
            resourceInputs["allowedRegistries"] = args ? args.allowedRegistries : undefined;
            resourceInputs["applicationScopes"] = args ? args.applicationScopes : undefined;
            resourceInputs["auditAllNetworkActivity"] = args ? args.auditAllNetworkActivity : undefined;
            resourceInputs["auditAllProcessesActivity"] = args ? args.auditAllProcessesActivity : undefined;
            resourceInputs["auditFullCommandArguments"] = args ? args.auditFullCommandArguments : undefined;
            resourceInputs["blockAccessHostNetwork"] = args ? args.blockAccessHostNetwork : undefined;
            resourceInputs["blockAddingCapabilities"] = args ? args.blockAddingCapabilities : undefined;
            resourceInputs["blockContainerExec"] = args ? args.blockContainerExec : undefined;
            resourceInputs["blockCryptocurrencyMining"] = args ? args.blockCryptocurrencyMining : undefined;
            resourceInputs["blockFilelessExec"] = args ? args.blockFilelessExec : undefined;
            resourceInputs["blockLowPortBinding"] = args ? args.blockLowPortBinding : undefined;
            resourceInputs["blockNonCompliantImages"] = args ? args.blockNonCompliantImages : undefined;
            resourceInputs["blockNonCompliantWorkloads"] = args ? args.blockNonCompliantWorkloads : undefined;
            resourceInputs["blockNonK8sContainers"] = args ? args.blockNonK8sContainers : undefined;
            resourceInputs["blockPrivilegedContainers"] = args ? args.blockPrivilegedContainers : undefined;
            resourceInputs["blockReverseShell"] = args ? args.blockReverseShell : undefined;
            resourceInputs["blockRootUser"] = args ? args.blockRootUser : undefined;
            resourceInputs["blockUnregisteredImages"] = args ? args.blockUnregisteredImages : undefined;
            resourceInputs["blockUseIpcNamespace"] = args ? args.blockUseIpcNamespace : undefined;
            resourceInputs["blockUsePidNamespace"] = args ? args.blockUsePidNamespace : undefined;
            resourceInputs["blockUseUserNamespace"] = args ? args.blockUseUserNamespace : undefined;
            resourceInputs["blockUseUtsNamespace"] = args ? args.blockUseUtsNamespace : undefined;
            resourceInputs["blockedCapabilities"] = args ? args.blockedCapabilities : undefined;
            resourceInputs["blockedExecutables"] = args ? args.blockedExecutables : undefined;
            resourceInputs["blockedFiles"] = args ? args.blockedFiles : undefined;
            resourceInputs["blockedInboundPorts"] = args ? args.blockedInboundPorts : undefined;
            resourceInputs["blockedOutboundPorts"] = args ? args.blockedOutboundPorts : undefined;
            resourceInputs["blockedPackages"] = args ? args.blockedPackages : undefined;
            resourceInputs["blockedVolumes"] = args ? args.blockedVolumes : undefined;
            resourceInputs["containerExecAllowedProcesses"] = args ? args.containerExecAllowedProcesses : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["enableDriftPrevention"] = args ? args.enableDriftPrevention : undefined;
            resourceInputs["enableForkGuard"] = args ? args.enableForkGuard : undefined;
            resourceInputs["enableIpReputationSecurity"] = args ? args.enableIpReputationSecurity : undefined;
            resourceInputs["enablePortScanDetection"] = args ? args.enablePortScanDetection : undefined;
            resourceInputs["enabled"] = args ? args.enabled : undefined;
            resourceInputs["enforce"] = args ? args.enforce : undefined;
            resourceInputs["enforceAfterDays"] = args ? args.enforceAfterDays : undefined;
            resourceInputs["exceptionalReadonlyFilesAndDirectories"] = args ? args.exceptionalReadonlyFilesAndDirectories : undefined;
            resourceInputs["fileIntegrityMonitoring"] = args ? args.fileIntegrityMonitoring : undefined;
            resourceInputs["forkGuardProcessLimit"] = args ? args.forkGuardProcessLimit : undefined;
            resourceInputs["limitNewPrivileges"] = args ? args.limitNewPrivileges : undefined;
            resourceInputs["malwareScanOptions"] = args ? args.malwareScanOptions : undefined;
            resourceInputs["monitorSystemTimeChanges"] = args ? args.monitorSystemTimeChanges : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["readonlyFilesAndDirectories"] = args ? args.readonlyFilesAndDirectories : undefined;
            resourceInputs["reverseShellAllowedIps"] = args ? args.reverseShellAllowedIps : undefined;
            resourceInputs["reverseShellAllowedProcesses"] = args ? args.reverseShellAllowedProcesses : undefined;
            resourceInputs["scopeExpression"] = args ? args.scopeExpression : undefined;
            resourceInputs["scopeVariables"] = args ? args.scopeVariables : undefined;
            resourceInputs["author"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ContainerRuntimePolicy.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ContainerRuntimePolicy resources.
 */
export interface ContainerRuntimePolicyState {
    /**
     * List of executables that are allowed for the user.
     */
    allowedExecutables?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of registries that allowed for running containers.
     */
    allowedRegistries?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Indicates the application scope of the service.
     */
    applicationScopes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * If true, all network activity will be audited.
     */
    auditAllNetworkActivity?: pulumi.Input<boolean>;
    /**
     * If true, all process activity will be audited.
     */
    auditAllProcessesActivity?: pulumi.Input<boolean>;
    /**
     * If true, full command arguments will be audited.
     */
    auditFullCommandArguments?: pulumi.Input<boolean>;
    /**
     * Username of the account that created the service.
     */
    author?: pulumi.Input<string>;
    /**
     * If true, prevent containers from running with access to host network.
     */
    blockAccessHostNetwork?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with adding capabilities with `--cap-add` privilege.
     */
    blockAddingCapabilities?: pulumi.Input<boolean>;
    /**
     * If true, exec into a container is prevented.
     */
    blockContainerExec?: pulumi.Input<boolean>;
    /**
     * Detect and prevent communication to DNS/IP addresses known to be used for Cryptocurrency Mining
     */
    blockCryptocurrencyMining?: pulumi.Input<boolean>;
    /**
     * Detect and prevent running in-memory execution
     */
    blockFilelessExec?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with the capability to bind in port lower than 1024.
     */
    blockLowPortBinding?: pulumi.Input<boolean>;
    /**
     * If true, running non-compliant image in the container is prevented.
     */
    blockNonCompliantImages?: pulumi.Input<boolean>;
    /**
     * If true, running containers in non-compliant pods is prevented.
     */
    blockNonCompliantWorkloads?: pulumi.Input<boolean>;
    /**
     * If true, running non-kubernetes containers is prevented.
     */
    blockNonK8sContainers?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with privileged container capability.
     */
    blockPrivilegedContainers?: pulumi.Input<boolean>;
    /**
     * If true, reverse shell is prevented.
     */
    blockReverseShell?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with root user.
     */
    blockRootUser?: pulumi.Input<boolean>;
    /**
     * If true, running images in the container that are not registered in Aqua is prevented.
     */
    blockUnregisteredImages?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with the privilege to use the IPC namespace.
     */
    blockUseIpcNamespace?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with the privilege to use the PID namespace.
     */
    blockUsePidNamespace?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with the privilege to use the user namespace.
     */
    blockUseUserNamespace?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with the privilege to use the UTS namespace.
     */
    blockUseUtsNamespace?: pulumi.Input<boolean>;
    /**
     * If true, prevents containers from using specific Unix capabilities.
     */
    blockedCapabilities?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of executables that are prevented from running in containers.
     */
    blockedExecutables?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of files that are prevented from being read, modified and executed in the containers.
     */
    blockedFiles?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of blocked inbound ports.
     */
    blockedInboundPorts?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of blocked outbound ports.
     */
    blockedOutboundPorts?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Prevent containers from reading, writing, or executing all files in the list of packages.
     */
    blockedPackages?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of volumes that are prevented from being mounted in the containers.
     */
    blockedVolumes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of processes that will be allowed.
     */
    containerExecAllowedProcesses?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The description of the container runtime policy
     */
    description?: pulumi.Input<string>;
    /**
     * If true, executables that are not in the original image is prevented from running.
     */
    enableDriftPrevention?: pulumi.Input<boolean>;
    /**
     * If true, fork bombs are prevented in the containers.
     */
    enableForkGuard?: pulumi.Input<boolean>;
    /**
     * If true, detect and prevent communication from containers to IP addresses known to have a bad reputation.
     */
    enableIpReputationSecurity?: pulumi.Input<boolean>;
    /**
     * If true, detects port scanning behavior in the container.
     */
    enablePortScanDetection?: pulumi.Input<boolean>;
    /**
     * Indicates if the runtime policy is enabled or not.
     */
    enabled?: pulumi.Input<boolean>;
    /**
     * Indicates that policy should effect container execution (not just for audit).
     */
    enforce?: pulumi.Input<boolean>;
    /**
     * Indicates the number of days after which the runtime policy will be changed to enforce mode.
     */
    enforceAfterDays?: pulumi.Input<number>;
    /**
     * List of files and directories to be excluded from the read-only list.
     */
    exceptionalReadonlyFilesAndDirectories?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Configuration for file integrity monitoring.
     */
    fileIntegrityMonitoring?: pulumi.Input<inputs.ContainerRuntimePolicyFileIntegrityMonitoring>;
    /**
     * Process limit for the fork guard.
     */
    forkGuardProcessLimit?: pulumi.Input<number>;
    /**
     * If true, prevents the container from obtaining new privileges at runtime. (only enabled in enforce mode)
     */
    limitNewPrivileges?: pulumi.Input<boolean>;
    /**
     * Configuration for Real-Time Malware Protection.
     */
    malwareScanOptions?: pulumi.Input<inputs.ContainerRuntimePolicyMalwareScanOptions>;
    /**
     * If true, system time changes will be monitored.
     */
    monitorSystemTimeChanges?: pulumi.Input<boolean>;
    /**
     * Name of the container runtime policy
     */
    name?: pulumi.Input<string>;
    /**
     * List of files and directories to be restricted as read-only
     */
    readonlyFilesAndDirectories?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of IPs/ CIDRs that will be allowed
     */
    reverseShellAllowedIps?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of processes that will be allowed
     */
    reverseShellAllowedProcesses?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Logical expression of how to compute the dependency of the scope variables.
     */
    scopeExpression?: pulumi.Input<string>;
    /**
     * List of scope attributes.
     */
    scopeVariables?: pulumi.Input<pulumi.Input<inputs.ContainerRuntimePolicyScopeVariable>[]>;
}

/**
 * The set of arguments for constructing a ContainerRuntimePolicy resource.
 */
export interface ContainerRuntimePolicyArgs {
    /**
     * List of executables that are allowed for the user.
     */
    allowedExecutables?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of registries that allowed for running containers.
     */
    allowedRegistries?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Indicates the application scope of the service.
     */
    applicationScopes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * If true, all network activity will be audited.
     */
    auditAllNetworkActivity?: pulumi.Input<boolean>;
    /**
     * If true, all process activity will be audited.
     */
    auditAllProcessesActivity?: pulumi.Input<boolean>;
    /**
     * If true, full command arguments will be audited.
     */
    auditFullCommandArguments?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with access to host network.
     */
    blockAccessHostNetwork?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with adding capabilities with `--cap-add` privilege.
     */
    blockAddingCapabilities?: pulumi.Input<boolean>;
    /**
     * If true, exec into a container is prevented.
     */
    blockContainerExec?: pulumi.Input<boolean>;
    /**
     * Detect and prevent communication to DNS/IP addresses known to be used for Cryptocurrency Mining
     */
    blockCryptocurrencyMining?: pulumi.Input<boolean>;
    /**
     * Detect and prevent running in-memory execution
     */
    blockFilelessExec?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with the capability to bind in port lower than 1024.
     */
    blockLowPortBinding?: pulumi.Input<boolean>;
    /**
     * If true, running non-compliant image in the container is prevented.
     */
    blockNonCompliantImages?: pulumi.Input<boolean>;
    /**
     * If true, running containers in non-compliant pods is prevented.
     */
    blockNonCompliantWorkloads?: pulumi.Input<boolean>;
    /**
     * If true, running non-kubernetes containers is prevented.
     */
    blockNonK8sContainers?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with privileged container capability.
     */
    blockPrivilegedContainers?: pulumi.Input<boolean>;
    /**
     * If true, reverse shell is prevented.
     */
    blockReverseShell?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with root user.
     */
    blockRootUser?: pulumi.Input<boolean>;
    /**
     * If true, running images in the container that are not registered in Aqua is prevented.
     */
    blockUnregisteredImages?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with the privilege to use the IPC namespace.
     */
    blockUseIpcNamespace?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with the privilege to use the PID namespace.
     */
    blockUsePidNamespace?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with the privilege to use the user namespace.
     */
    blockUseUserNamespace?: pulumi.Input<boolean>;
    /**
     * If true, prevent containers from running with the privilege to use the UTS namespace.
     */
    blockUseUtsNamespace?: pulumi.Input<boolean>;
    /**
     * If true, prevents containers from using specific Unix capabilities.
     */
    blockedCapabilities?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of executables that are prevented from running in containers.
     */
    blockedExecutables?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of files that are prevented from being read, modified and executed in the containers.
     */
    blockedFiles?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of blocked inbound ports.
     */
    blockedInboundPorts?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of blocked outbound ports.
     */
    blockedOutboundPorts?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Prevent containers from reading, writing, or executing all files in the list of packages.
     */
    blockedPackages?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of volumes that are prevented from being mounted in the containers.
     */
    blockedVolumes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of processes that will be allowed.
     */
    containerExecAllowedProcesses?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The description of the container runtime policy
     */
    description?: pulumi.Input<string>;
    /**
     * If true, executables that are not in the original image is prevented from running.
     */
    enableDriftPrevention?: pulumi.Input<boolean>;
    /**
     * If true, fork bombs are prevented in the containers.
     */
    enableForkGuard?: pulumi.Input<boolean>;
    /**
     * If true, detect and prevent communication from containers to IP addresses known to have a bad reputation.
     */
    enableIpReputationSecurity?: pulumi.Input<boolean>;
    /**
     * If true, detects port scanning behavior in the container.
     */
    enablePortScanDetection?: pulumi.Input<boolean>;
    /**
     * Indicates if the runtime policy is enabled or not.
     */
    enabled?: pulumi.Input<boolean>;
    /**
     * Indicates that policy should effect container execution (not just for audit).
     */
    enforce?: pulumi.Input<boolean>;
    /**
     * Indicates the number of days after which the runtime policy will be changed to enforce mode.
     */
    enforceAfterDays?: pulumi.Input<number>;
    /**
     * List of files and directories to be excluded from the read-only list.
     */
    exceptionalReadonlyFilesAndDirectories?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Configuration for file integrity monitoring.
     */
    fileIntegrityMonitoring?: pulumi.Input<inputs.ContainerRuntimePolicyFileIntegrityMonitoring>;
    /**
     * Process limit for the fork guard.
     */
    forkGuardProcessLimit?: pulumi.Input<number>;
    /**
     * If true, prevents the container from obtaining new privileges at runtime. (only enabled in enforce mode)
     */
    limitNewPrivileges?: pulumi.Input<boolean>;
    /**
     * Configuration for Real-Time Malware Protection.
     */
    malwareScanOptions?: pulumi.Input<inputs.ContainerRuntimePolicyMalwareScanOptions>;
    /**
     * If true, system time changes will be monitored.
     */
    monitorSystemTimeChanges?: pulumi.Input<boolean>;
    /**
     * Name of the container runtime policy
     */
    name?: pulumi.Input<string>;
    /**
     * List of files and directories to be restricted as read-only
     */
    readonlyFilesAndDirectories?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of IPs/ CIDRs that will be allowed
     */
    reverseShellAllowedIps?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of processes that will be allowed
     */
    reverseShellAllowedProcesses?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Logical expression of how to compute the dependency of the scope variables.
     */
    scopeExpression?: pulumi.Input<string>;
    /**
     * List of scope attributes.
     */
    scopeVariables?: pulumi.Input<pulumi.Input<inputs.ContainerRuntimePolicyScopeVariable>[]>;
}
