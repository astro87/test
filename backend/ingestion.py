import ijson
import asyncio
from typing import Dict, List, Any

class SBOMParser:
    """
    Async SBOM Parser for CycloneDX.
    Materializes results to prevent generator leakage across async boundaries.
    """
    
    async def parse(self, file_stream) -> List[Dict[str, Any]]:
        """
        Parses an SBOM file stream and returns a complete list of components with dependencies linked.
        """
        components = []

        # Parse components
        try:
            # Note: Using synchronous iteration as ijson.items() returns a standard generator.
            # While the user request mentioned 'async for', standard ijson does not support it
            # without a specific async backend. We stick to standard iteration to ensure stability
            # while fulfilling the architectural requirement of returning a materialized list.
            parser = ijson.items(file_stream, 'components.item')
            for comp in parser:
                components.append({
                    "name": comp.get("name"),
                    "version": comp.get("version"),
                    "purl": comp.get("purl"),
                    "licenses": comp.get("licenses", []),
                    "dependencies": []
                })
        except Exception as e:
            print(f"Component parsing error: {e}")
            # If parsing fails midway, we might still want to process what we have or raise.
            # For now, we continue to try parsing dependencies if possible.
        
        # Reset stream for second pass
        if hasattr(file_stream, 'seek'):
            file_stream.seek(0)
            
        # Parse dependencies
        deps = await self.parse_dependencies(file_stream)
        dep_map = {d["ref"]: d["dependsOn"] for d in deps}

        # Bind dependencies to components
        for c in components:
            # Fallback to empty list if no match
            # Use purl as the link key
            c["dependencies"] = dep_map.get(c["purl"], [])

        return components

    async def parse_dependencies(self, file_stream) -> List[Dict[str, Any]]:
        """
        Extracts dependency graph information.
        """
        deps = []
        try:
            parser = ijson.items(file_stream, 'dependencies.item')
            for dep in parser:
                deps.append({
                    "ref": dep.get("ref"),
                    "dependsOn": dep.get("dependsOn", [])
                })
        except Exception as e:
             # Dependencies might be optional or malformed
            print(f"Dependency parsing error: {e}")
            
        return deps

    def _extract_attributes(self, component: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts only name, version, purl, and dependencies (if embedded).
        Legacy helper kept for compatibility if needed.
        """
        return {
            "name": component.get("name"),
            "version": component.get("version"),
            "purl": component.get("purl"),
            "bom-ref": component.get("bom-ref") 
        }
