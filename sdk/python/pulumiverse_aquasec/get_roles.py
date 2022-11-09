# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from . import _utilities
from . import outputs

__all__ = [
    'GetRolesResult',
    'AwaitableGetRolesResult',
    'get_roles',
]

@pulumi.output_type
class GetRolesResult:
    """
    A collection of values returned by getRoles.
    """
    def __init__(__self__, id=None, roles=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if roles and not isinstance(roles, list):
            raise TypeError("Expected argument 'roles' to be a list")
        pulumi.set(__self__, "roles", roles)

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def roles(self) -> Sequence['outputs.GetRolesRoleResult']:
        return pulumi.get(self, "roles")


class AwaitableGetRolesResult(GetRolesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetRolesResult(
            id=self.id,
            roles=self.roles)


def get_roles(opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetRolesResult:
    """
    The data source `get_roles` provides a method to query all roles within the Aqua account managementrole database. The fields returned from this query are detailed in the Schema section below.
    """
    __args__ = dict()
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('aquasec:index/getRoles:getRoles', __args__, opts=opts, typ=GetRolesResult).value

    return AwaitableGetRolesResult(
        id=__ret__.id,
        roles=__ret__.roles)
