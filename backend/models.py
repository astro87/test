from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

class JobStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class Vulnerability(BaseModel):
    id: str
    severity: str
    cvss: float
    description: Optional[str] = None

class Component(BaseModel):
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    bom_ref: Optional[str] = Field(None, alias="bom-ref")
    vulnerabilities: List[Vulnerability] = []
    risk_score: float = 0.0
    final_risk_score: float = 0.0

class JobStats(BaseModel):
    total_components: int = 0
    vulnerable_components: int = 0
    risk_distribution: Dict[str, int] = {}

class GraphData(BaseModel):
    nodes: List[Dict[str, str]]
    edges: List[Dict[str, str]]

class JobResultData(BaseModel):
    components: List[Dict[str, Any]]  # Keeping loose for flexibility, or List[Component]
    summary: Optional[str] = None
    stats: JobStats
    graph: GraphData

class JobResult(BaseModel):
    job_id: str
    status: JobStatus
    progress: int = 0
    stages: Dict[str, int] = {}
    data: Optional[JobResultData] = None
    error: Optional[str] = None
