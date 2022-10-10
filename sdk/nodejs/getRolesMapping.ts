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
 * const rolesMapping = aquasec.getRolesMapping({});
 * export const roleMappingAll = rolesMapping;
 * export const roleMappingSaml = rolesMapping.then(rolesMapping => rolesMapping.samls);
 * ```
 */
export function getRolesMapping(opts?: pulumi.InvokeOptions): Promise<GetRolesMappingResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("aquasec:index/getRolesMapping:getRolesMapping", {
    }, opts);
}

/**
 * A collection of values returned by getRolesMapping.
 */
export interface GetRolesMappingResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Oauth2 Authentication
     */
    readonly oauth2s: outputs.GetRolesMappingOauth2[];
    /**
     * OpenId Authentication
     */
    readonly openids: outputs.GetRolesMappingOpenid[];
    /**
     * SAML Authentication
     */
    readonly samls: outputs.GetRolesMappingSaml[];
}
