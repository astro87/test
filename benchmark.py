import asyncio
import json
import time
import os
import io
from backend.ingestion import SBOMParser
from backend.graph import DependencyGraph
from backend.matcher import VulnMatcher
from backend.ml import RiskModel
from backend.reasoning import ReasoningEngine
from backend.vuln_db import VulnDB

async def run_benchmark():
    # 1. Generate Synthetic Large SBOM
    print("Generating synthetic SBOM...")
    component_count = 1000
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [],
        "dependencies": []
    }
    
    for i in range(component_count):
        ref = f"pkg:npm/lib-{i}@{i}.0.0"
        sbom["components"].append({
            "name": f"lib-{i}",
            "version": f"{i}.0.0",
            "purl": ref,
            "bom-ref": ref
        })
        # Create a simple chain: i depends on i+1
        if i < component_count - 1:
            sbom["dependencies"].append({
                "ref": ref,
                "dependsOn": [f"pkg:npm/lib-{i+1}@{i+1}.0.0"]
            })
            
    # Save to file to test streaming
    with open("data/benchmark_sbom.json", "w") as f:
        json.dump(sbom, f)
        
    # Populate DB with some hits
    db = VulnDB("data/vuln.db")
    # Mark every 10th lib as vulnerable
    for i in range(0, component_count, 10):
        db.insert_vuln(f"lib-{i}", "0.0.0", "999.0.0", f"CVE-2024-{i}", "HIGH", 8.0)
    
    print("Starting Benchmark...")
    
    # SETUP
    parser = SBOMParser()
    matcher = VulnMatcher("data/vuln.db")
    ml = RiskModel()
    reasoning = ReasoningEngine()
    
    # 1. PARSING (Streaming)
    start = time.time()
    components = []
    with open("data/benchmark_sbom.json", "rb") as f:
        async for comp in parser.parse(f):
            components.append(comp)
            
    with open("data/benchmark_sbom.json", "rb") as f:
        deps = await parser.parse_dependencies(f)
    parse_time = (time.time() - start) * 1000
    print(f"Parsing ({component_count} items): {parse_time:.2f} ms (Target: < 300ms)")
    
    # 2. GRAPH BUILD
    start = time.time()
    graph = DependencyGraph()
    graph.build(components, deps)
    # Calculate depth for all nodes to simulate full analysis
    root = components[0]['bom-ref']
    depths = graph.calculate_depth(root)
    graph_time = (time.time() - start) * 1000
    print(f"Graph Build: {graph_time:.2f} ms (Target: < 150ms)")
    
    # 3. CVE MATCHING
    start = time.time()
    matched = matcher.match_components(components)
    match_time = (time.time() - start) * 1000
    print(f"CVE Matching: {match_time:.2f} ms (Target: < 500ms)")
    
    # 4. ML INFERENCE
    start = time.time()
    scored = ml.batch_predict(matched, depths)
    ml_time = (time.time() - start) * 1000
    print(f"ML Inference: {ml_time:.2f} ms (Target: < 100ms)")
    
    # 5. REASONING
    start = time.time()
    final = reasoning.analyze(scored, graph)
    reason_time = (time.time() - start) * 1000
    print(f"Reasoning: {reason_time:.2f} ms (Target: < 80ms)")
    
    total_time = parse_time + graph_time + match_time + ml_time + reason_time
    print(f"Total Time: {total_time:.2f} ms")
    
    # Verify Targets
    assert parse_time < 300
    assert graph_time < 150
    assert match_time < 500
    assert ml_time < 100
    assert reason_time < 80
    assert total_time < 1200
    
    print("\nBENCHMARK PASSED!")

if __name__ == "__main__":
    asyncio.run(run_benchmark())
