import unittest
import json
import io
import asyncio
from backend.ingestion import SBOMParser

class TestSBOMParser(unittest.IsolatedAsyncioTestCase):
    async def test_parse_cyclonedx(self):
        # Sample CycloneDX JSON content
        sample_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "name": "library-a",
                    "version": "1.0.0",
                    "purl": "pkg:npm/library-a@1.0.0",
                    "bom-ref": "pkg:npm/library-a@1.0.0"
                },
                {
                    "name": "library-b",
                    "version": "2.1.0",
                    "purl": "pkg:npm/library-b@2.1.0",
                    "bom-ref": "pkg:npm/library-b@2.1.0"
                }
            ],
            "dependencies": [
                 {
                    "ref": "pkg:npm/library-a@1.0.0",
                    "dependsOn": [
                        "pkg:npm/library-b@2.1.0"
                    ]
                 }
            ]
        }
        
        # Convert to bytes for ijson
        json_bytes = json.dumps(sample_sbom).encode('utf-8')
        file_stream = io.BytesIO(json_bytes)
        
        parser = SBOMParser()
        components = []
        async for comp in parser.parse(file_stream):
            components.append(comp)
            
        self.assertEqual(len(components), 2)
        self.assertEqual(components[0]['name'], 'library-a')
        self.assertEqual(components[1]['purl'], 'pkg:npm/library-b@2.1.0')

        # Test dependencies
        # Note: In real stream, we can't read same stream twice without seek
        file_stream.seek(0)
        deps = await parser.parse_dependencies(file_stream)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]['ref'], "pkg:npm/library-a@1.0.0")
        self.assertEqual(deps[0]['dependsOn'], ["pkg:npm/library-b@2.1.0"])

if __name__ == '__main__':
    unittest.main()
