"""
Prompt Injection Simulator — FastAPI backend.

Phases implemented:
  1  Scope & learning objectives  →  six named attack scenarios
  2  Sandboxed environment        →  claude-haiku target + .env API key
  3  Attack scenario library      →  scenarios.py
  4  Defence & detection          →  detection.py  (input validation + canary + LLM judge)
  5  UI & reporting               →  static/index.html  + /report endpoint

Run:
    uvicorn main:app --reload

EDUCATIONAL USE ONLY.
"""
from __future__ import annotations

import datetime
import os
from pathlib import Path
from typing import List

import anthropic
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from rich.console import Console

from models import ScenarioInfo, SessionReport, SimulationRequest, SimulationResult
from scenarios import SCENARIOS
from simulator import LOG_FILE, run_simulation

load_dotenv()
console = Console()

app = FastAPI(
    title="Prompt Injection Simulator",
    description=(
        "Educational tool for understanding LLM prompt injection attacks and defences. "
        "EDUCATIONAL USE ONLY."
    ),
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory="static"), name="static")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _client() -> anthropic.Anthropic:
    key = os.getenv("ANTHROPIC_API_KEY", "")
    if not key:
        raise HTTPException(
            status_code=500,
            detail="ANTHROPIC_API_KEY is not set. Copy .env.example → .env and add your key.",
        )
    return anthropic.Anthropic(api_key=key)


def _load_history() -> list[SimulationResult]:
    if not LOG_FILE.exists():
        return []
    results: list[SimulationResult] = []
    with LOG_FILE.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                results.append(SimulationResult.model_validate_json(line))
    return results


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index():
    return Path("static/index.html").read_text()


@app.get("/scenarios", response_model=List[ScenarioInfo], tags=["Scenarios"])
async def list_scenarios():
    """Return all available attack scenarios."""
    return list(SCENARIOS.values())


@app.get("/scenarios/{scenario_id}", response_model=ScenarioInfo, tags=["Scenarios"])
async def get_scenario(scenario_id: str):
    """Return details for a single scenario."""
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")
    return SCENARIOS[scenario_id]


@app.post("/simulate", response_model=SimulationResult, tags=["Simulation"])
async def simulate(request: SimulationRequest):
    """
    Run a prompt injection simulation.

    - Builds the correct prompt structure for the attack surface.
    - Calls claude-haiku as the sandboxed target model.
    - Runs all three detection layers (regex, canary, LLM judge).
    - Returns a full result with VULNERABLE / DEFENDED verdict.
    - Appends the run to simulation_log.jsonl.
    """
    client = _client()
    try:
        return run_simulation(client, request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        console.print_exception()
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/history", response_model=List[SimulationResult], tags=["Reporting"])
async def history():
    """Return all past simulation runs from simulation_log.jsonl."""
    return _load_history()


@app.delete("/history", tags=["Reporting"])
async def clear_history():
    """Delete the simulation log."""
    if LOG_FILE.exists():
        LOG_FILE.unlink()
    return {"message": "History cleared."}


@app.get("/report", response_model=SessionReport, tags=["Reporting"])
async def report():
    """Generate an aggregate session report."""
    runs = _load_history()
    return SessionReport(
        generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        total_runs=len(runs),
        vulnerable_count=sum(1 for r in runs if r.verdict == "VULNERABLE"),
        defended_count=sum(1 for r in runs if r.verdict == "DEFENDED"),
        results=runs,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
