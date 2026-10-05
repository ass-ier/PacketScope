from pydantic import BaseModel, ConfigDict, Field
from typing import Literal


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RuleUpdate(StrictModel):
    enabled: bool | None = None
    config: dict | None = None
    attack_mapping: list[str] | None = None


class CaseCreate(StrictModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=20000)


class CaseUpdate(StrictModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=20000)
    status: Literal["Open", "Investigating", "Contained", "Closed", "False Positive"] | None = None
    verdict: Literal["Benign", "Suspicious", "Malicious", "Unknown"] | None = None
    confidence: Literal["Low", "Medium", "High"] | None = None
    reasoning: str | None = Field(default=None, max_length=20000)


class CaseLinkCreate(StrictModel):
    kind: Literal["capture", "host", "ioc", "finding"]
    entity_id: str = Field(min_length=36, max_length=36)


class NoteCreate(StrictModel):
    text: str = Field(min_length=1, max_length=20000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=200)


class CompareCreate(StrictModel):
    baseline_id: str = Field(min_length=36, max_length=36)
    comparison_id: str = Field(min_length=36, max_length=36)


class ExtractionCreate(StrictModel):
    acknowledge_untrusted: bool = False


class IntelLookup(StrictModel):
    provider: Literal["rdap", "dns", "virustotal"]
    consent_to_share_indicator: bool = False


class ReportCreate(StrictModel):
    capture_id: str = Field(min_length=36, max_length=36)
    case_id: str | None = Field(default=None, min_length=36, max_length=36)
    format: Literal["pdf", "markdown", "json", "stix"]
