import asyncio
import time
import os
import shutil
from typing import Dict, Optional, List, Any
from concurrent.futures import Executor

from backend.models import JobResult, JobStatus, JobResultData, JobStats, GraphData
from backend.ingestion import SBOMParser
from backend.graph import DependencyGraph
from backend.matcher import VulnMatcher
from backend.ml import RiskModel
from backend.reasoning import ReasoningEngine

# Global singleton or passed in - we'll simulate singleton access or dependency injection
# For now, we initialize them here or expect them to be passed.
# Ideally, main.py initializes them and passes them to the controller.

class PipelineController:
    def __init__(self, 
                 parser: SBOMParser,
                 matcher: VulnMatcher,
                 ml_model: RiskModel,
                 reasoning: ReasoningEngine):
        self.parser = parser
        self.matcher = matcher
        self.ml_model = ml_model
        self.reasoning = reasoning
        
        # In-memory job store (replace with Redis/DB in prod)
        self.jobs: Dict[str, JobResult] = {}
        self.event_queues: Dict[str, asyncio.Queue] = {}

    def create_job(self, job_id: str) -> JobResult:
        job = JobResult(
            job_id=job_id,
            status=JobStatus.PENDING,
            progress=0,
            stages={}
        )
        self.jobs[job_id] = job
        self.event_queues[job_id] = asyncio.Queue()
        return job

    def get_job(self, job_id: str) -> Optional[JobResult]:
        return self.jobs.get(job_id)

    def get_event_queue(self, job_id: str) -> Optional[asyncio.Queue]:
        return self.event_queues.get(job_id)

    async def emit_update(self, job_id: str):
        """Pushes the current job state to the SSE queue."""
        q = self.event_queues.get(job_id)
        job = self.jobs.get(job_id)
        if q and job:
            # We serialize the Pydantic model to dict
            await q.put(job.dict())

    def _assert_not_generator(self, obj: Any, name: str = "Object"):
        """
        CRITICAL ARCHITECTURAL GUARD:
        Ensures that an object is NOT a generator.
        Generators are execution cursors, not data. They must never leak.
        """
        if hasattr(obj, "__next__") or hasattr(obj, "__iter__") and not isinstance(obj, (list, tuple, dict, str, bytes, set)):
             # Check for generator specifically or other iterators that are not containers
             # Note: simple iterators on my_list are also iterators. 
             # We specifically want to block generator objects.
             import inspect
             if inspect.isgenerator(obj):
                raise RuntimeError(f"ARCHITECTURE ERROR: Generator leaked in {name}. Generators must be materialized immediately.")

    async def start_analysis(self, job_id: str, file_path: str, webhook_url: Optional[str] = None):
        """
        Main orchestration entry point.
        """
        loop = asyncio.get_running_loop()
        job = self.jobs.get(job_id)
        if not job:
            return

        try:
            job.status = JobStatus.PROCESSING
            await self.emit_update(job_id)

            # 1. Parsing (Async Stream)
            start_t = time.time()
            
            # Using new async parse method with stream
            with open(file_path, "rb") as f:
                components = await self.parser.parse(f)
            
            self._assert_not_generator(components, "Parsing Stage (Components)")
            
            # Reconstruct deps list for graph builder
            deps = [{"ref": c.get("purl"), "dependsOn": c.get("dependencies", [])} for c in components]
            
            job.stages["parsing_ms"] = int((time.time() - start_t) * 1000)
            job.progress = 20
            await self.emit_update(job_id)

            # 2. Graph Build
            start_t = time.time()
            graph, depths = await loop.run_in_executor(None, self._build_graph, components, deps)
            job.stages["graph_ms"] = int((time.time() - start_t) * 1000)
            job.progress = 40
            await self.emit_update(job_id)

            # 3. CVE Matching
            start_t = time.time()
            matched_components = await loop.run_in_executor(None, self.matcher.match_components, components)
            self._assert_not_generator(matched_components, "Matching Stage")
            
            job.stages["matching_ms"] = int((time.time() - start_t) * 1000)
            job.progress = 60
            await self.emit_update(job_id)

            # 4. ML Inference
            start_t = time.time()
            # Assuming ml_model.batch_predict takes components and their depths
            scored_components = await loop.run_in_executor(None, self.ml_model.batch_predict, matched_components, depths)
            self._assert_not_generator(scored_components, "ML Stage")
            
            job.stages["ml_ms"] = int((time.time() - start_t) * 1000)
            job.progress = 80
            await self.emit_update(job_id)

            # 5. Reasoning
            start_t = time.time()
            final_components = await loop.run_in_executor(None, self.reasoning.analyze, scored_components, graph)
            self._assert_not_generator(final_components, "Reasoning Stage")
            
            summary = await loop.run_in_executor(None, self.reasoning.generate_system_summary, final_components)
            self._assert_not_generator(summary, "Summary Generation")
            
            job.stages["reasoning_ms"] = int((time.time() - start_t) * 1000)

            # Finalize
            job.status = JobStatus.COMPLETED
            job.progress = 100
            
            # Construct JobResultData
            stats = JobStats(
                total_components=len(components),
                vulnerable_components=len([c for c in final_components if c.get('vulnerabilities')]),
                risk_distribution=self._calculate_distribution(final_components)
            )
            
            graph_data = GraphData(
                nodes=[{"id": str(n), "label": str(n)} for n in graph.graph.nodes()],
                edges=[{"source": str(u), "target": str(v)} for u, v in graph.graph.edges()]
            )
            
            job.data = JobResultData(
                components=final_components,
                summary=summary,
                stats=stats,
                graph=graph_data
            )
            
            await self.emit_update(job_id)
            
            if webhook_url:
                print(f"Webhook triggered: {webhook_url}")

        except Exception as e:
            print(f"Job {job_id} failed: {e}")
            job.status = JobStatus.FAILED
            job.error = str(e)
            await self.emit_update(job_id)
        finally:
            # Cleanup file
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass

    def _build_graph(self, components, deps):
        # Helper to isolate graph logic
        g = DependencyGraph()
        g.build(components, deps)
        r = components[0]['bom-ref'] if components and 'bom-ref' in components[0] else "root"
        d = g.calculate_depth(r)
        return g, d

    def _calculate_distribution(self, components):
        dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "SAFE": 0}
        for c in components:
            score = c.get('final_risk_score', 0)
            if score == 0: dist["SAFE"] += 1
            elif score < 40: dist["LOW"] += 1
            elif score < 70: dist["MEDIUM"] += 1
            elif score < 90: dist["HIGH"] += 1
            else: dist["CRITICAL"] += 1
        return dist
