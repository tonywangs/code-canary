#!/usr/bin/env python3
"""
Test parsers for different package managers.
"""

import pytest
import tempfile
import json
from pathlib import Path

from dependency_canary.parsers.python import PythonParser
from dependency_canary.parsers.javascript import JavaScriptParser
from dependency_canary.parsers.golang import GoParser
from dependency_canary.models import DependencyType


class TestPythonParser:
    """Test Python package parser."""
    
    @pytest.mark.asyncio
    async def test_parse_requirements_txt(self):
        """Test parsing requirements.txt."""
        parser = PythonParser()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            requirements_file = tmppath / "requirements.txt"
            
            requirements_file.write_text("""
# Core dependencies
requests==2.25.1
click>=8.0.0
numpy~=1.20.0

# Optional dependencies
pytest==7.1.0  # Testing framework
""")
            
            dependencies = await parser.parse_manifest(requirements_file)
            
            assert len(dependencies) == 4
            
            # Check specific packages
            package_names = [dep.package.name for dep in dependencies]
            assert "requests" in package_names
            assert "click" in package_names
            assert "numpy" in package_names
            assert "pytest" in package_names
            
            # Check versions
            requests_dep = next(dep for dep in dependencies if dep.package.name == "requests")
            assert requests_dep.package.version == "2.25.1"
    
    @pytest.mark.asyncio
    async def test_parse_pyproject_toml(self):
        """Test parsing pyproject.toml."""
        parser = PythonParser()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            pyproject_file = tmppath / "pyproject.toml"
            
            pyproject_file.write_text("""
[tool.poetry]
name = "test-project"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.8"
requests = "^2.25.0"
click = "8.0.0"

[tool.poetry.dev-dependencies]
pytest = "^7.0.0"
black = "^22.0.0"
""")
            
            dependencies = await parser.parse_manifest(pyproject_file)
            
            assert len(dependencies) == 4  # requests, click, pytest, black
            
            # Check that dev dependencies are marked correctly
            dev_deps = [dep for dep in dependencies if dep.dependency_type == DependencyType.DEV]
            assert len(dev_deps) == 2
            
            dev_names = [dep.package.name for dep in dev_deps]
            assert "pytest" in dev_names
            assert "black" in dev_names


class TestJavaScriptParser:
    """Test JavaScript/Node.js package parser."""
    
    @pytest.mark.asyncio
    async def test_parse_package_json(self):
        """Test parsing package.json."""
        parser = JavaScriptParser()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            package_file = tmppath / "package.json"
            
            package_data = {
                "name": "test-project",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "^4.17.21",
                    "express": "4.18.0",
                    "axios": "~0.27.0"
                },
                "devDependencies": {
                    "jest": "^28.0.0",
                    "typescript": "4.7.4"
                }
            }
            
            package_file.write_text(json.dumps(package_data, indent=2))
            
            dependencies = await parser.parse_manifest(package_file)
            
            assert len(dependencies) == 5
            
            # Check regular dependencies
            regular_deps = [dep for dep in dependencies if dep.dependency_type == DependencyType.DIRECT]
            assert len(regular_deps) == 3
            
            regular_names = [dep.package.name for dep in regular_deps]
            assert "lodash" in regular_names
            assert "express" in regular_names
            assert "axios" in regular_names
            
            # Check dev dependencies
            dev_deps = [dep for dep in dependencies if dep.dependency_type == DependencyType.DEV]
            assert len(dev_deps) == 2
            
            dev_names = [dep.package.name for dep in dev_deps]
            assert "jest" in dev_names
            assert "typescript" in dev_names
    
    @pytest.mark.asyncio
    async def test_parse_package_lock_json(self):
        """Test parsing package-lock.json."""
        parser = JavaScriptParser()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            lock_file = tmppath / "package-lock.json"
            
            lock_data = {
                "name": "test-project",
                "version": "1.0.0",
                "lockfileVersion": 2,
                "packages": {
                    "": {
                        "name": "test-project",
                        "version": "1.0.0"
                    },
                    "node_modules/lodash": {
                        "version": "4.17.21",
                        "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                    },
                    "node_modules/express": {
                        "version": "4.18.0",
                        "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz"
                    }
                }
            }
            
            lock_file.write_text(json.dumps(lock_data, indent=2))
            
            dependencies = await parser.parse_lockfile(lock_file)
            
            assert len(dependencies) == 2
            
            package_names = [dep.package.name for dep in dependencies]
            assert "lodash" in package_names
            assert "express" in package_names
            
            # These particular dependencies should be marked as direct (depth 0 in node_modules/)
            for dep in dependencies:
                assert dep.dependency_type == DependencyType.DIRECT


class TestGoParser:
    """Test Go package parser."""
    
    @pytest.mark.asyncio
    async def test_parse_go_mod(self):
        """Test parsing go.mod."""
        parser = GoParser()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            go_mod_file = tmppath / "go.mod"
            
            go_mod_file.write_text("""
module github.com/example/myproject

go 1.19

require (
    github.com/gin-gonic/gin v1.8.1
    github.com/stretchr/testify v1.8.0
    golang.org/x/net v0.0.0-20220722155237-a158d28d115b
)

require github.com/gorilla/mux v1.8.0
""")
            
            dependencies = await parser.parse_manifest(go_mod_file)
            
            assert len(dependencies) == 4
            
            package_names = [dep.package.name for dep in dependencies]
            assert "github.com/gin-gonic/gin" in package_names
            assert "github.com/stretchr/testify" in package_names
            assert "golang.org/x/net" in package_names
            assert "github.com/gorilla/mux" in package_names
            
            # Check versions
            gin_dep = next(dep for dep in dependencies if dep.package.name == "github.com/gin-gonic/gin")
            assert gin_dep.package.version == "v1.8.1"
    
    @pytest.mark.asyncio
    async def test_parse_go_sum(self):
        """Test parsing go.sum."""
        parser = GoParser()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            go_sum_file = tmppath / "go.sum"
            
            go_sum_file.write_text("""
github.com/gin-gonic/gin v1.8.1 h1:4+fr/el88TOO3ewCmQr8cx/CtZ/umlIRIs5M4NTNjf8=
github.com/gin-gonic/gin v1.8.1/go.mod h1:ji8BvRH1azfM+SYow9zQ6SZMvR8qOMdHAHaTQx6YyL0=
github.com/stretchr/testify v1.8.0 h1:pSgiaMZlXftHpm5L7V1+rVB+AZJydKsMxsQBIJw4PKk=
github.com/stretchr/testify v1.8.0/go.mod h1:yNjHg4UonilssWZ8iaSj1OCr/vHnekPRkoO+kdMU+MU=
""")
            
            dependencies = await parser.parse_lockfile(go_sum_file)
            
            assert len(dependencies) == 2
            
            package_names = [dep.package.name for dep in dependencies]
            assert "github.com/gin-gonic/gin" in package_names
            assert "github.com/stretchr/testify" in package_names
            
            # go.sum dependencies should be marked as transitive
            for dep in dependencies:
                assert dep.dependency_type == DependencyType.TRANSITIVE


class TestParserErrorHandling:
    """Test parser error handling."""
    
    @pytest.mark.asyncio
    async def test_parse_invalid_json(self):
        """Test parsing invalid JSON files."""
        parser = JavaScriptParser()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            invalid_file = tmppath / "package.json"
            
            invalid_file.write_text("{invalid json content}")
            
            # Should not raise exception, just return empty list
            dependencies = await parser.parse_manifest(invalid_file)
            assert dependencies == []
    
    @pytest.mark.asyncio
    async def test_parse_nonexistent_file(self):
        """Test parsing nonexistent files."""
        parser = PythonParser()
        
        nonexistent_file = Path("/tmp/nonexistent/requirements.txt")
        
        # Should not raise exception, just return empty list
        dependencies = await parser.parse_manifest(nonexistent_file)
        assert dependencies == []


if __name__ == "__main__":
    pytest.main([__file__])