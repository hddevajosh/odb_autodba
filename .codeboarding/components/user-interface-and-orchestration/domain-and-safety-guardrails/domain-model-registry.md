---
component_id: 1.5.1
component_name: Domain Model Registry
---

# Domain Model Registry

## Component Description

Defines the unified data language of the system using Pydantic models to validate Oracle database entities and structures AI agent output into actionable remediation proposals.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/models/schemas.py (lines 29-40)
```
class InstanceInfo(BaseModel):
    instance_name: str = ""
    host_name: str = ""
    version: str = ""
    startup_time: str = ""
    db_name: str = ""
    db_unique_name: str = ""
    open_mode: str = ""
    database_role: str = ""
    platform_name: str = ""
    rac_enabled: bool = False
    cdb: str | None = None
```

### /home/neha/projects/agents/odb_autodba/models/schemas.py (lines 53-70)
```
class SessionRow(BaseModel):
    inst_id: int | None = None
    sid: int
    serial_num: int | None = None
    username: str | None = None
    status: str | None = None
    sql_id: str | None = None
    event: str | None = None
    wait_class: str | None = None
    module: str | None = None
    program: str | None = None
    machine: str | None = None
    seconds_in_wait: int | None = None
    last_call_et: int | None = None
    blocking_instance: int | None = None
    blocking_session: int | None = None

    model_config = ConfigDict(populate_by_name=True)
```

### /home/neha/projects/agents/odb_autodba/models/schemas.py (lines 1336-1350)
```
class RemediationProposal(BaseModel):
    action_type: str
    title: str
    description: str
    rationale: str
    target: dict[str, Any] = Field(default_factory=dict)
    sql: str | None = None
    risks: list[str] = Field(default_factory=list)
    safer_alternatives: list[str] = Field(default_factory=list)
    validation_plan: list[str] = Field(default_factory=list)
    post_action_validation: PostActionValidationPlan | None = None
    reason_for_action: str = ""
    execution_sql: str | None = None
    blocking_action: BlockingActionProposal | None = None
    confidence: ReviewConfidence = "MEDIUM"
```


## Source Files:

- `guardrails/models.py`
- `models/schemas.py`

