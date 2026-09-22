"""CIDAS analysis pillars package.

Each pillar is a class with an async ``score()`` method that returns a
``PillarScore``.  Import the classes directly from their modules to keep
instantiation explicit and testable.
"""
from .contextify import Contextify
from .sentinel import Sentinel
from .shield import Shield
from .aggregator import Aggregator

__all__ = ["Contextify", "Sentinel", "Shield", "Aggregator"]
