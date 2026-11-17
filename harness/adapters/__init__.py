"""Optional model adapters.

Nothing in this package is required for tests, examples or the benchmark: all of those
use the offline stub in :mod:`harness.simulated_app`. The adapters exist so you can see
how to wire the firewall into a real client without copying code out of a blog post.

Each adapter imports its vendor SDK *inside* the function, so the base package has no
model-provider dependency at all.
"""

from __future__ import annotations

ADAPTERS = ("openai_compatible", "anthropic_messages", "local_transformers")

__all__ = ["ADAPTERS"]
