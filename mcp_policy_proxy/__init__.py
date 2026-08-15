"""mcp_policy_proxy — MCP policy proxy with enforcement + compound endpoints.

Adapted from the original policy-proxy/mcp package for distribution as a pip
package. Depends on ``mcp2cli`` and ``skills-server`` (via pip) for the shared
MCP client library and the skills MCP server.
"""

from mcp_policy_proxy import policy_proxy as policy_proxy  # noqa: F401
from mcp_policy_proxy import mounted_server as mounted_server  # noqa: F401
from mcp_policy_proxy import policy_yaml as policy_yaml  # noqa: F401
from mcp_policy_proxy import validate_policy as validate_policy  # noqa: F401

__version__ = "0.1.0"

__all__ = [
    "policy_proxy",
    "mounted_server",
    "policy_yaml",
    "validate_policy",
    "__version__",
]