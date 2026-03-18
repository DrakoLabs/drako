# ok: MULTI-001
# Multi-agent system WITH topology monitoring configured
from crewai import Agent

researcher = Agent(name="researcher", role="Research Agent")
writer = Agent(name="writer", role="Writing Agent")
reviewer = Agent(name="reviewer", role="Review Agent")

# Topology monitoring is enabled via drako observability
from drako import topology

topology.enable(
    conflict_detection=True,
    cascade_amplification=True,
)
