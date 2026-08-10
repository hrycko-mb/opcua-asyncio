import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from io import BytesIO

from asyncua import ua
from asyncua.common import utils

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

ADMIN_TYPES = [
    ua.ObjectIds.RegisterServerRequest_Encoding_DefaultBinary,
    ua.ObjectIds.RegisterServer2Request_Encoding_DefaultBinary,
    ua.ObjectIds.AddNodesRequest_Encoding_DefaultBinary,
    ua.ObjectIds.DeleteNodesRequest_Encoding_DefaultBinary,
    ua.ObjectIds.AddReferencesRequest_Encoding_DefaultBinary,
    ua.ObjectIds.DeleteReferencesRequest_Encoding_DefaultBinary,
]

USER_TYPES = [
    ua.ObjectIds.CreateSessionRequest_Encoding_DefaultBinary,
    ua.ObjectIds.CloseSessionRequest_Encoding_DefaultBinary,
    ua.ObjectIds.ActivateSessionRequest_Encoding_DefaultBinary,
    ua.ObjectIds.ReadRequest_Encoding_DefaultBinary,
    ua.ObjectIds.WriteRequest_Encoding_DefaultBinary,
    ua.ObjectIds.BrowseRequest_Encoding_DefaultBinary,
    ua.ObjectIds.GetEndpointsRequest_Encoding_DefaultBinary,
    ua.ObjectIds.FindServersRequest_Encoding_DefaultBinary,
    ua.ObjectIds.TranslateBrowsePathsToNodeIdsRequest_Encoding_DefaultBinary,
    ua.ObjectIds.CreateSubscriptionRequest_Encoding_DefaultBinary,
    ua.ObjectIds.ModifySubscriptionRequest_Encoding_DefaultBinary,
    ua.ObjectIds.DeleteSubscriptionsRequest_Encoding_DefaultBinary,
    ua.ObjectIds.TransferSubscriptionsRequest_Encoding_DefaultBinary,
    ua.ObjectIds.CreateMonitoredItemsRequest_Encoding_DefaultBinary,
    ua.ObjectIds.ModifyMonitoredItemsRequest_Encoding_DefaultBinary,
    ua.ObjectIds.DeleteMonitoredItemsRequest_Encoding_DefaultBinary,
    ua.ObjectIds.HistoryReadRequest_Encoding_DefaultBinary,
    ua.ObjectIds.PublishRequest_Encoding_DefaultBinary,
    ua.ObjectIds.RepublishRequest_Encoding_DefaultBinary,
    ua.ObjectIds.CloseSecureChannelRequest_Encoding_DefaultBinary,
    ua.ObjectIds.CallRequest_Encoding_DefaultBinary,
    ua.ObjectIds.SetMonitoringModeRequest_Encoding_DefaultBinary,
    ua.ObjectIds.SetPublishingModeRequest_Encoding_DefaultBinary,
    ua.ObjectIds.RegisterNodesRequest_Encoding_DefaultBinary,
    ua.ObjectIds.UnregisterNodesRequest_Encoding_DefaultBinary,
]


class UserRole(Enum):
    """
    User Roles
    """

    Admin = 0
    Anonymous = 1
    User = 3


@dataclass
class User:
    role: UserRole = UserRole.Anonymous
    name: str | None = None


class PermissionRuleset(ABC):
    """
    Base class for permission ruleset
    """

    @abstractmethod
    def check_validity(self, user: User, action_type: ua.ObjectIds, body: BytesIO | utils.Buffer) -> bool: ...


class SimpleRoleRuleset(PermissionRuleset):
    """
    Standard simple role-based ruleset.
    Admins alone can change address space, admins and users can read/write, and anonymous users can't do anything.
    """

    def __init__(self) -> None:
        admin_ids = list(map(ua.NodeId, ADMIN_TYPES))
        user_ids = list(map(ua.NodeId, USER_TYPES))
        self._permission_dict = {
            UserRole.Admin: set().union(admin_ids, user_ids),
            UserRole.User: set().union(user_ids),
            UserRole.Anonymous: set(),
        }

    @override
    def check_validity(self, user: User, action_type: ua.ObjectIds, body: BytesIO | utils.Buffer) -> bool:
        if action_type in self._permission_dict[user.role]:
            return True
        return False
