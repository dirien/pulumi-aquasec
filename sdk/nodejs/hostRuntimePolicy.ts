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
 * const hostRuntimePolicy = new aquasec.HostRuntimePolicy("host_runtime_policy", {
 *     auditAllOsUserActivity: true,
 *     auditBruteForceLogin: true,
 *     auditFullCommandArguments: true,
 *     auditHostFailedLoginEvents: true,
 *     auditHostSuccessfulLoginEvents: true,
 *     auditUserAccountManagement: true,
 *     blockCryptocurrencyMining: true,
 *     blockedFiles: ["blocked"],
 *     description: "host_runtime_policy",
 *     enableIpReputationSecurity: true,
 *     enabled: true,
 *     enforce: false,
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
 *     monitorSystemLogIntegrity: true,
 *     monitorSystemTimeChanges: true,
 *     monitorWindowsServices: true,
 *     osGroupsAlloweds: ["group1"],
 *     osGroupsBlockeds: ["group2"],
 *     osUsersAlloweds: ["user1"],
 *     osUsersBlockeds: ["user2"],
 *     packageBlocks: ["package1"],
 *     portScanningDetection: true,
 *     windowsRegistryMonitoring: {
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
 *     windowsRegistryProtection: {
 *         excludedPaths: ["expaths"],
 *         excludedProcesses: ["exprocess"],
 *         excludedUsers: ["expuser"],
 *         protectedPaths: ["paths"],
 *         protectedProcesses: ["process"],
 *         protectedUsers: ["user"],
 *     },
 * });
 * ```
 */
export class HostRuntimePolicy extends pulumi.CustomResource {
    /**
     * Get an existing HostRuntimePolicy resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: HostRuntimePolicyState, opts?: pulumi.CustomResourceOptions): HostRuntimePolicy {
        return new HostRuntimePolicy(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'aquasec:index/hostRuntimePolicy:HostRuntimePolicy';

    /**
     * Returns true if the given object is an instance of HostRuntimePolicy.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is HostRuntimePolicy {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === HostRuntimePolicy.__pulumiType;
    }

    /**
     * Indicates the application scope of the service.
     */
    public readonly applicationScopes!: pulumi.Output<string[]>;
    /**
     * If true, all process activity will be audited.
     */
    public readonly auditAllOsUserActivity!: pulumi.Output<boolean | undefined>;
    /**
     * Detects brute force login attempts
     */
    public readonly auditBruteForceLogin!: pulumi.Output<boolean | undefined>;
    /**
     * If true, full command arguments will be audited.
     */
    public readonly auditFullCommandArguments!: pulumi.Output<boolean | undefined>;
    /**
     * If true, host failed logins will be audited.
     */
    public readonly auditHostFailedLoginEvents!: pulumi.Output<boolean | undefined>;
    /**
     * If true, host successful logins will be audited.
     */
    public readonly auditHostSuccessfulLoginEvents!: pulumi.Output<boolean | undefined>;
    /**
     * If true, account management will be audited.
     */
    public readonly auditUserAccountManagement!: pulumi.Output<boolean | undefined>;
    /**
     * Username of the account that created the service.
     */
    public /*out*/ readonly author!: pulumi.Output<string>;
    /**
     * Detect and prevent communication to DNS/IP addresses known to be used for Cryptocurrency Mining
     */
    public readonly blockCryptocurrencyMining!: pulumi.Output<boolean | undefined>;
    /**
     * List of files that are prevented from being read, modified and executed in the containers.
     */
    public readonly blockedFiles!: pulumi.Output<string[] | undefined>;
    /**
     * The description of the host runtime policy
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * If true, detect and prevent communication from containers to IP addresses known to have a bad reputation.
     */
    public readonly enableIpReputationSecurity!: pulumi.Output<boolean | undefined>;
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
     * Configuration for file integrity monitoring.
     */
    public readonly fileIntegrityMonitoring!: pulumi.Output<outputs.HostRuntimePolicyFileIntegrityMonitoring | undefined>;
    /**
     * Configuration for Real-Time Malware Protection.
     */
    public readonly malwareScanOptions!: pulumi.Output<outputs.HostRuntimePolicyMalwareScanOptions | undefined>;
    /**
     * If true, system log will be monitored.
     */
    public readonly monitorSystemLogIntegrity!: pulumi.Output<boolean | undefined>;
    /**
     * If true, system time changes will be monitored.
     */
    public readonly monitorSystemTimeChanges!: pulumi.Output<boolean | undefined>;
    /**
     * If true, windows service operations will be monitored.
     */
    public readonly monitorWindowsServices!: pulumi.Output<boolean | undefined>;
    /**
     * Name of the host runtime policy
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * List of OS (Linux or Windows) groups that are allowed to authenticate to the host, and block authentication requests from all others. Groups can be either Linux groups or Windows AD groups.
     */
    public readonly osGroupsAlloweds!: pulumi.Output<string[] | undefined>;
    /**
     * List of OS (Linux or Windows) groups that are not allowed to authenticate to the host, and block authentication requests from all others. Groups can be either Linux groups or Windows AD groups.
     */
    public readonly osGroupsBlockeds!: pulumi.Output<string[] | undefined>;
    /**
     * List of OS (Linux or Windows) users that are allowed to authenticate to the host, and block authentication requests from all others.
     */
    public readonly osUsersAlloweds!: pulumi.Output<string[] | undefined>;
    /**
     * List of OS (Linux or Windows) users that are not allowed to authenticate to the host, and block authentication requests from all others.
     */
    public readonly osUsersBlockeds!: pulumi.Output<string[] | undefined>;
    /**
     * List of packages that are not allowed read, write or execute all files that under the packages.
     */
    public readonly packageBlocks!: pulumi.Output<string[] | undefined>;
    /**
     * If true, port scanning behaviors will be audited.
     */
    public readonly portScanningDetection!: pulumi.Output<boolean | undefined>;
    /**
     * Logical expression of how to compute the dependency of the scope variables.
     */
    public readonly scopeExpression!: pulumi.Output<string>;
    /**
     * List of scope attributes.
     */
    public readonly scopeVariables!: pulumi.Output<outputs.HostRuntimePolicyScopeVariable[]>;
    /**
     * Configuration for windows registry monitoring.
     */
    public readonly windowsRegistryMonitoring!: pulumi.Output<outputs.HostRuntimePolicyWindowsRegistryMonitoring | undefined>;
    /**
     * Configuration for windows registry protection.
     */
    public readonly windowsRegistryProtection!: pulumi.Output<outputs.HostRuntimePolicyWindowsRegistryProtection | undefined>;

    /**
     * Create a HostRuntimePolicy resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: HostRuntimePolicyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: HostRuntimePolicyArgs | HostRuntimePolicyState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as HostRuntimePolicyState | undefined;
            resourceInputs["applicationScopes"] = state ? state.applicationScopes : undefined;
            resourceInputs["auditAllOsUserActivity"] = state ? state.auditAllOsUserActivity : undefined;
            resourceInputs["auditBruteForceLogin"] = state ? state.auditBruteForceLogin : undefined;
            resourceInputs["auditFullCommandArguments"] = state ? state.auditFullCommandArguments : undefined;
            resourceInputs["auditHostFailedLoginEvents"] = state ? state.auditHostFailedLoginEvents : undefined;
            resourceInputs["auditHostSuccessfulLoginEvents"] = state ? state.auditHostSuccessfulLoginEvents : undefined;
            resourceInputs["auditUserAccountManagement"] = state ? state.auditUserAccountManagement : undefined;
            resourceInputs["author"] = state ? state.author : undefined;
            resourceInputs["blockCryptocurrencyMining"] = state ? state.blockCryptocurrencyMining : undefined;
            resourceInputs["blockedFiles"] = state ? state.blockedFiles : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["enableIpReputationSecurity"] = state ? state.enableIpReputationSecurity : undefined;
            resourceInputs["enabled"] = state ? state.enabled : undefined;
            resourceInputs["enforce"] = state ? state.enforce : undefined;
            resourceInputs["enforceAfterDays"] = state ? state.enforceAfterDays : undefined;
            resourceInputs["fileIntegrityMonitoring"] = state ? state.fileIntegrityMonitoring : undefined;
            resourceInputs["malwareScanOptions"] = state ? state.malwareScanOptions : undefined;
            resourceInputs["monitorSystemLogIntegrity"] = state ? state.monitorSystemLogIntegrity : undefined;
            resourceInputs["monitorSystemTimeChanges"] = state ? state.monitorSystemTimeChanges : undefined;
            resourceInputs["monitorWindowsServices"] = state ? state.monitorWindowsServices : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["osGroupsAlloweds"] = state ? state.osGroupsAlloweds : undefined;
            resourceInputs["osGroupsBlockeds"] = state ? state.osGroupsBlockeds : undefined;
            resourceInputs["osUsersAlloweds"] = state ? state.osUsersAlloweds : undefined;
            resourceInputs["osUsersBlockeds"] = state ? state.osUsersBlockeds : undefined;
            resourceInputs["packageBlocks"] = state ? state.packageBlocks : undefined;
            resourceInputs["portScanningDetection"] = state ? state.portScanningDetection : undefined;
            resourceInputs["scopeExpression"] = state ? state.scopeExpression : undefined;
            resourceInputs["scopeVariables"] = state ? state.scopeVariables : undefined;
            resourceInputs["windowsRegistryMonitoring"] = state ? state.windowsRegistryMonitoring : undefined;
            resourceInputs["windowsRegistryProtection"] = state ? state.windowsRegistryProtection : undefined;
        } else {
            const args = argsOrState as HostRuntimePolicyArgs | undefined;
            resourceInputs["applicationScopes"] = args ? args.applicationScopes : undefined;
            resourceInputs["auditAllOsUserActivity"] = args ? args.auditAllOsUserActivity : undefined;
            resourceInputs["auditBruteForceLogin"] = args ? args.auditBruteForceLogin : undefined;
            resourceInputs["auditFullCommandArguments"] = args ? args.auditFullCommandArguments : undefined;
            resourceInputs["auditHostFailedLoginEvents"] = args ? args.auditHostFailedLoginEvents : undefined;
            resourceInputs["auditHostSuccessfulLoginEvents"] = args ? args.auditHostSuccessfulLoginEvents : undefined;
            resourceInputs["auditUserAccountManagement"] = args ? args.auditUserAccountManagement : undefined;
            resourceInputs["blockCryptocurrencyMining"] = args ? args.blockCryptocurrencyMining : undefined;
            resourceInputs["blockedFiles"] = args ? args.blockedFiles : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["enableIpReputationSecurity"] = args ? args.enableIpReputationSecurity : undefined;
            resourceInputs["enabled"] = args ? args.enabled : undefined;
            resourceInputs["enforce"] = args ? args.enforce : undefined;
            resourceInputs["enforceAfterDays"] = args ? args.enforceAfterDays : undefined;
            resourceInputs["fileIntegrityMonitoring"] = args ? args.fileIntegrityMonitoring : undefined;
            resourceInputs["malwareScanOptions"] = args ? args.malwareScanOptions : undefined;
            resourceInputs["monitorSystemLogIntegrity"] = args ? args.monitorSystemLogIntegrity : undefined;
            resourceInputs["monitorSystemTimeChanges"] = args ? args.monitorSystemTimeChanges : undefined;
            resourceInputs["monitorWindowsServices"] = args ? args.monitorWindowsServices : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["osGroupsAlloweds"] = args ? args.osGroupsAlloweds : undefined;
            resourceInputs["osGroupsBlockeds"] = args ? args.osGroupsBlockeds : undefined;
            resourceInputs["osUsersAlloweds"] = args ? args.osUsersAlloweds : undefined;
            resourceInputs["osUsersBlockeds"] = args ? args.osUsersBlockeds : undefined;
            resourceInputs["packageBlocks"] = args ? args.packageBlocks : undefined;
            resourceInputs["portScanningDetection"] = args ? args.portScanningDetection : undefined;
            resourceInputs["scopeExpression"] = args ? args.scopeExpression : undefined;
            resourceInputs["scopeVariables"] = args ? args.scopeVariables : undefined;
            resourceInputs["windowsRegistryMonitoring"] = args ? args.windowsRegistryMonitoring : undefined;
            resourceInputs["windowsRegistryProtection"] = args ? args.windowsRegistryProtection : undefined;
            resourceInputs["author"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(HostRuntimePolicy.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering HostRuntimePolicy resources.
 */
export interface HostRuntimePolicyState {
    /**
     * Indicates the application scope of the service.
     */
    applicationScopes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * If true, all process activity will be audited.
     */
    auditAllOsUserActivity?: pulumi.Input<boolean>;
    /**
     * Detects brute force login attempts
     */
    auditBruteForceLogin?: pulumi.Input<boolean>;
    /**
     * If true, full command arguments will be audited.
     */
    auditFullCommandArguments?: pulumi.Input<boolean>;
    /**
     * If true, host failed logins will be audited.
     */
    auditHostFailedLoginEvents?: pulumi.Input<boolean>;
    /**
     * If true, host successful logins will be audited.
     */
    auditHostSuccessfulLoginEvents?: pulumi.Input<boolean>;
    /**
     * If true, account management will be audited.
     */
    auditUserAccountManagement?: pulumi.Input<boolean>;
    /**
     * Username of the account that created the service.
     */
    author?: pulumi.Input<string>;
    /**
     * Detect and prevent communication to DNS/IP addresses known to be used for Cryptocurrency Mining
     */
    blockCryptocurrencyMining?: pulumi.Input<boolean>;
    /**
     * List of files that are prevented from being read, modified and executed in the containers.
     */
    blockedFiles?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The description of the host runtime policy
     */
    description?: pulumi.Input<string>;
    /**
     * If true, detect and prevent communication from containers to IP addresses known to have a bad reputation.
     */
    enableIpReputationSecurity?: pulumi.Input<boolean>;
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
     * Configuration for file integrity monitoring.
     */
    fileIntegrityMonitoring?: pulumi.Input<inputs.HostRuntimePolicyFileIntegrityMonitoring>;
    /**
     * Configuration for Real-Time Malware Protection.
     */
    malwareScanOptions?: pulumi.Input<inputs.HostRuntimePolicyMalwareScanOptions>;
    /**
     * If true, system log will be monitored.
     */
    monitorSystemLogIntegrity?: pulumi.Input<boolean>;
    /**
     * If true, system time changes will be monitored.
     */
    monitorSystemTimeChanges?: pulumi.Input<boolean>;
    /**
     * If true, windows service operations will be monitored.
     */
    monitorWindowsServices?: pulumi.Input<boolean>;
    /**
     * Name of the host runtime policy
     */
    name?: pulumi.Input<string>;
    /**
     * List of OS (Linux or Windows) groups that are allowed to authenticate to the host, and block authentication requests from all others. Groups can be either Linux groups or Windows AD groups.
     */
    osGroupsAlloweds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of OS (Linux or Windows) groups that are not allowed to authenticate to the host, and block authentication requests from all others. Groups can be either Linux groups or Windows AD groups.
     */
    osGroupsBlockeds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of OS (Linux or Windows) users that are allowed to authenticate to the host, and block authentication requests from all others.
     */
    osUsersAlloweds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of OS (Linux or Windows) users that are not allowed to authenticate to the host, and block authentication requests from all others.
     */
    osUsersBlockeds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of packages that are not allowed read, write or execute all files that under the packages.
     */
    packageBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * If true, port scanning behaviors will be audited.
     */
    portScanningDetection?: pulumi.Input<boolean>;
    /**
     * Logical expression of how to compute the dependency of the scope variables.
     */
    scopeExpression?: pulumi.Input<string>;
    /**
     * List of scope attributes.
     */
    scopeVariables?: pulumi.Input<pulumi.Input<inputs.HostRuntimePolicyScopeVariable>[]>;
    /**
     * Configuration for windows registry monitoring.
     */
    windowsRegistryMonitoring?: pulumi.Input<inputs.HostRuntimePolicyWindowsRegistryMonitoring>;
    /**
     * Configuration for windows registry protection.
     */
    windowsRegistryProtection?: pulumi.Input<inputs.HostRuntimePolicyWindowsRegistryProtection>;
}

/**
 * The set of arguments for constructing a HostRuntimePolicy resource.
 */
export interface HostRuntimePolicyArgs {
    /**
     * Indicates the application scope of the service.
     */
    applicationScopes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * If true, all process activity will be audited.
     */
    auditAllOsUserActivity?: pulumi.Input<boolean>;
    /**
     * Detects brute force login attempts
     */
    auditBruteForceLogin?: pulumi.Input<boolean>;
    /**
     * If true, full command arguments will be audited.
     */
    auditFullCommandArguments?: pulumi.Input<boolean>;
    /**
     * If true, host failed logins will be audited.
     */
    auditHostFailedLoginEvents?: pulumi.Input<boolean>;
    /**
     * If true, host successful logins will be audited.
     */
    auditHostSuccessfulLoginEvents?: pulumi.Input<boolean>;
    /**
     * If true, account management will be audited.
     */
    auditUserAccountManagement?: pulumi.Input<boolean>;
    /**
     * Detect and prevent communication to DNS/IP addresses known to be used for Cryptocurrency Mining
     */
    blockCryptocurrencyMining?: pulumi.Input<boolean>;
    /**
     * List of files that are prevented from being read, modified and executed in the containers.
     */
    blockedFiles?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The description of the host runtime policy
     */
    description?: pulumi.Input<string>;
    /**
     * If true, detect and prevent communication from containers to IP addresses known to have a bad reputation.
     */
    enableIpReputationSecurity?: pulumi.Input<boolean>;
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
     * Configuration for file integrity monitoring.
     */
    fileIntegrityMonitoring?: pulumi.Input<inputs.HostRuntimePolicyFileIntegrityMonitoring>;
    /**
     * Configuration for Real-Time Malware Protection.
     */
    malwareScanOptions?: pulumi.Input<inputs.HostRuntimePolicyMalwareScanOptions>;
    /**
     * If true, system log will be monitored.
     */
    monitorSystemLogIntegrity?: pulumi.Input<boolean>;
    /**
     * If true, system time changes will be monitored.
     */
    monitorSystemTimeChanges?: pulumi.Input<boolean>;
    /**
     * If true, windows service operations will be monitored.
     */
    monitorWindowsServices?: pulumi.Input<boolean>;
    /**
     * Name of the host runtime policy
     */
    name?: pulumi.Input<string>;
    /**
     * List of OS (Linux or Windows) groups that are allowed to authenticate to the host, and block authentication requests from all others. Groups can be either Linux groups or Windows AD groups.
     */
    osGroupsAlloweds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of OS (Linux or Windows) groups that are not allowed to authenticate to the host, and block authentication requests from all others. Groups can be either Linux groups or Windows AD groups.
     */
    osGroupsBlockeds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of OS (Linux or Windows) users that are allowed to authenticate to the host, and block authentication requests from all others.
     */
    osUsersAlloweds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of OS (Linux or Windows) users that are not allowed to authenticate to the host, and block authentication requests from all others.
     */
    osUsersBlockeds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * List of packages that are not allowed read, write or execute all files that under the packages.
     */
    packageBlocks?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * If true, port scanning behaviors will be audited.
     */
    portScanningDetection?: pulumi.Input<boolean>;
    /**
     * Logical expression of how to compute the dependency of the scope variables.
     */
    scopeExpression?: pulumi.Input<string>;
    /**
     * List of scope attributes.
     */
    scopeVariables?: pulumi.Input<pulumi.Input<inputs.HostRuntimePolicyScopeVariable>[]>;
    /**
     * Configuration for windows registry monitoring.
     */
    windowsRegistryMonitoring?: pulumi.Input<inputs.HostRuntimePolicyWindowsRegistryMonitoring>;
    /**
     * Configuration for windows registry protection.
     */
    windowsRegistryProtection?: pulumi.Input<inputs.HostRuntimePolicyWindowsRegistryProtection>;
}
