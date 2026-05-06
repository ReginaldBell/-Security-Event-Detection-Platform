from pydantic import BaseModel
from typing import Optional

# Locked canonical field list. Update normalization, detection, tests, and
# dashboard/public/schema.json when this list changes.
CANONICAL_FIELDS = [
    "timestamp",     # ISO 8601 UTC - required
    "source_ip",     # originating IP address or host - optional
    "username",      # authenticated principal - optional
    "event_type",    # action category, e.g. login_attempt - required
    "result",        # success | failure - required
    "reason",        # failure reason / error message - optional
    "user_agent",    # HTTP user-agent string - optional
    "process_name",  # process executable name for EDR events - optional
    "command_line",  # process command line for EDR events - optional
    "location",      # geo/location hint for VPN/cloud auth events - optional
    "source",        # log source system name - optional
    "event_id",      # stable scenario/source event identifier - optional
    "scenario_id",   # validation scenario identifier - optional
    "validation_run_id",  # deterministic validation run identifier - optional
    "raw_source",    # original raw log line, JSON-serialized for audit
]


class NormalizedEventNew(BaseModel):
    timestamp: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: str = "login_attempt"
    result: str
    reason: Optional[str] = None
    user_agent: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    location: Optional[str] = None
    source: str = "auth_service"
    event_id: Optional[str] = None
    scenario_id: Optional[str] = None
    validation_run_id: Optional[str] = None
    raw_source: Optional[str] = None
