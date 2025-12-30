from fastapi import FastAPI, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import shutil
import os
import time
import asyncio
import json
from sse_starlette.sse import EventSourceResponse
from pydantic import BaseModel

from backend.ingestion import SBOMParser
from backend.matcher import VulnMatcher
from backend.ml import RiskModel
from backend.reasoning import ReasoningEngine
from backend.controller import PipelineController

# Initialize FastAPI
app = FastAPI(title="VULNERA-MAP", description="Advanced SBOM Vulnerability Detection System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Component Initialization ---
if not os.path.exists("data"):
    os.makedirs("data")

if not os.path.exists("data/vuln.db"):
    from backend.vuln_db import VulnDB
    VulnDB("data/vuln.db").populate_mock_data()

# Initialize core components
parser = SBOMParser()
matcher = VulnMatcher("data/vuln.db")
ml_model = RiskModel()
reasoning = ReasoningEngine()

# Initialize Controller
controller = PipelineController(
    parser=parser,
    matcher=matcher,
    ml_model=ml_model,
    reasoning=reasoning
)

# --- API Models ---
class UploadResponse(BaseModel):
    job_id: str
    message: str

# --- Endpoints ---

@app.get("/api/health")
async def health_check():
    return {"status": "ok"}

@app.post("/api/upload", response_model=UploadResponse)
async def upload_sbom(
    file: UploadFile = File(...), 
    webhook_url: Optional[str] = None
):
    """
    Accepts SBOM file, starts async analysis, returns job ID.
    Job lifecycle is now managed by PipelineController.
    """
    job_id = f"job_{int(time.time())}"
    
    # Save file temporarily
    file_path = f"data/{job_id}_{file.filename}"
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    # Create job in controller
    controller.create_job(job_id)
    
    # Start background task via controller
    asyncio.create_task(controller.start_analysis(job_id, file_path, webhook_url))
    
    return {"job_id": job_id, "message": "Analysis started"}

@app.get("/api/events/{job_id}")
async def job_events(job_id: str):
    """
    Server-Sent Events endpoint for job progress.
    """
    async def event_generator():
        queue = controller.get_event_queue(job_id)
        job = controller.get_job(job_id)

        if not queue:
            # If job exists but queue missing/cleaned up, try to return final state
            if job:
                yield json.dumps(job.dict())
            return

        # Yield current state immediately upon connection
        if job:
            yield json.dumps(job.dict())

        while True:
            try:
                # Wait for new event
                data = await asyncio.wait_for(queue.get(), timeout=1.0)
                # data is already a dict from controller
                yield json.dumps(data)
                
                if data.get("status") in ["completed", "failed"]:
                    break
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
                continue
            except asyncio.CancelledError:
                break
    
    return EventSourceResponse(event_generator())

@app.get("/api/results/{job_id}")
async def get_results(job_id: str):
    job = controller.get_job(job_id)
    if not job:
        return {"status": "not_found"}
    return job.dict()

@app.post("/api/admin/update-rules")
async def update_rules():
    """
    Mock endpoint to trigger rule/DB updates.
    """
    return {"status": "rules_updated", "version": "2023.10.01"}

# Mount frontend at the end
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
