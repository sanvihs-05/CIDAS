"""Contextify pillar — AST-based project context extraction.

Steps
-----
1. ``load_project_fingerprint``: parse package.json dependencies + walk src/
   files for import statements using tree-sitter; build a list of tech domains.
2. ``embed_project``: embed the domain list into a single vector via the
   EmbeddingService; store/retrieve from ChromaDB for persistence.
3. ``fetch_package_description``: retrieve the package description from the
   npm registry to get an embedding anchor for the candidate.
4. ``compute_score``: cosine similarity between the candidate embedding and
   the project fingerprint, inverted to a risk score.

A high similarity → the package fits the project context → low risk.
A low similarity in a large project → unfamiliar pattern → moderate risk.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path

from ..models import PillarScore
from ..utils.embeddings import cosine_similarity, embed_text
from ..utils.logger import get_logger
from ..utils.npm_registry import RegistryLookup, get_package_metadata

log = get_logger(__name__)

_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
_MAX_FILES = 150
_IMPORT_RE = re.compile(r"""(?:from|require)\s*\(?['"]([^'"]+)['"]\)?""")


class Contextify:
    """Pillar 1: assess how well a candidate package fits the project context."""

    async def score(self, package_name: str, project_path: str) -> PillarScore:
        """Return a PillarScore for the candidate package."""
        if not project_path:
            return PillarScore(
                score=5.0,
                confidence=0.3,
                flags=["no_project_path"],
                metadata={"skipped": True},
            )

        domains = await asyncio.to_thread(self.load_project_fingerprint, project_path)

        if not domains:
            return PillarScore(
                score=5.0,
                confidence=0.3,
                flags=["empty_project"],
                metadata={"project_path": project_path},
            )

        # TODO(phase-2): persist project embedding to ChromaDB and retrieve on repeat scans
        project_vec = await self.embed_project(domains)
        pkg_description = await self.fetch_package_description(package_name)
        anchor = pkg_description or package_name
        pkg_vec = await asyncio.to_thread(embed_text, anchor)

        similarity = cosine_similarity(project_vec, pkg_vec)
        score, flags = self.compute_score(similarity, len(domains))

        return PillarScore(
            score=score,
            confidence=0.7,
            flags=flags,
            metadata={
                "similarity": round(float(similarity), 4),
                "domain_count": len(domains),
                "anchor": anchor[:80],
            },
        )

    def load_project_fingerprint(self, project_path: str) -> list[str]:
        """Return a deduplicated list of module names imported in the project."""
        root = Path(project_path)
        if not root.is_dir():
            return []

        domains: set[str] = set()

        # Pull declared dependencies from package.json
        pkg_json = root / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                domains.update(data.get("dependencies", {}).keys())
                domains.update(data.get("devDependencies", {}).keys())
            except (json.JSONDecodeError, OSError):
                pass

        # TODO(phase-2): full tree-sitter AST traversal for import graphs
        files_scanned = 0
        done = False
        for dirpath, dirs, files in os.walk(str(root)):
            # Prune node_modules before descending — avoids crawling thousands of files
            dirs[:] = [d for d in dirs if d != "node_modules"]
            for name in files:
                if files_scanned >= _MAX_FILES:
                    done = True
                    break
                if not any(name.endswith(ext) for ext in _EXTENSIONS):
                    continue
                try:
                    source = Path(dirpath, name).read_text(encoding="utf-8", errors="ignore")
                    for match in _IMPORT_RE.finditer(source):
                        spec = match.group(1)
                        if not spec.startswith("."):
                            domains.add(spec.split("/")[0].lstrip("@").split("/")[0])
                    files_scanned += 1
                except OSError:
                    continue
            if done:
                break

        return list(domains)

    async def embed_project(self, domains: list[str]) -> list[float]:
        """Embed the joined domain list; wraps synchronous model call."""
        text = " ".join(sorted(domains))
        return await asyncio.to_thread(embed_text, text)

    async def fetch_package_description(self, package_name: str) -> str | None:
        """Return the npm registry description for the candidate package."""
        try:
            result = await get_package_metadata(package_name)
            if result.status is RegistryLookup.EXISTS and result.data:
                return result.data.get("description") or None
        except Exception as exc:
            log.debug("description fetch failed for %s: %s", package_name, exc)
        return None

    def compute_score(self, similarity: float, domain_count: int) -> tuple[float, list[str]]:
        """Map cosine similarity to a risk score and flag list."""
        flags: list[str] = []
        if similarity >= 0.65:
            return 0.0, flags
        if similarity >= 0.35:
            flags.append("loosely_related")
            return 10.0, flags
        if domain_count > 10:
            flags.append("unfamiliar_in_mature_project")
            return 25.0, flags
        flags.append("unfamiliar_package")
        return 15.0, flags
