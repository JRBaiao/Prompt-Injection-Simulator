"""
Pydantic data models for the Prompt Injection Simulator.

EDUCATIONAL USE ONLY — demonstrates LLM prompt injection vulnerabilities.
"""
from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel


class AttackType(str, Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_HIJACK = "role_hijack"
    CONTEXT_SMUGGLING = "context_smuggling"
    DELIMITER_ESCAPE = "delimiter_escape"
    GOAL_HIJACK = "goal_hijack"
    DATA_EXFILTRATION = "data_exfiltration"


class InjectionSurface(str, Enum):
    DIRECT = "direct"   # Attacker injects directly in the user turn
    RAG = "rag"         # Injection hidden inside retrieved documents
    AGENT = "agent"     # Injection embedded in tool outputs / agent chain


# ── Request / Response ────────────────────────────────────────────────────────

class SimulationRequest(BaseModel):
    scenario_id: str
    custom_payload: Optional[str] = None   # None → use scenario default
    mitigation_enabled: bool = False


class DetectionResult(BaseModel):
    input_flagged: bool            # Input validation caught the payload
    output_flagged: bool           # Output classifier flagged the response
    canary_leaked: bool            # System-prompt canary appeared in output
    complied_with_injection: bool  # LLM judge: model obeyed the injection
    confidence: float              # Judge confidence 0.0–1.0
    judge_reasoning: str           # Judge's explanation


class SimulationResult(BaseModel):
    run_id: str
    timestamp: str
    scenario_id: str
    scenario_name: str
    attack_type: AttackType
    surface: InjectionSurface
    system_prompt: str
    user_input: str            # Full message seen by the target model
    injected_payload: str      # The raw injection payload
    model_output: str
    detection: DetectionResult
    verdict: str               # "VULNERABLE" | "DEFENDED"
    mitigation_applied: Optional[str]
    educational_note: str


# ── Scenario catalogue entry ──────────────────────────────────────────────────

class ExamplePayload(BaseModel):
    label: str        # Short name shown in the UI, e.g. "Obvious" / "Subtle"
    payload: str
    why_it_works: str # One-line explanation shown on hover / debrief


class ScenarioInfo(BaseModel):
    id: str
    name: str
    attack_type: AttackType
    surface: InjectionSurface
    description: str
    educational_note: str
    default_payload: str
    example_payloads: List[ExamplePayload] = []
    mitigation_technique: str
    expected_vulnerable_behavior: str
    expected_safe_behavior: str


# ── Session report ────────────────────────────────────────────────────────────

class SessionReport(BaseModel):
    generated_at: str
    total_runs: int
    vulnerable_count: int
    defended_count: int
    results: List[SimulationResult]
