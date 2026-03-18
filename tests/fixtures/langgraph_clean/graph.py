"""Clean LangGraph project with good governance for testing."""
import os
from typing import TypedDict

from langgraph.graph import StateGraph, END
from tenacity import retry, stop_after_attempt, wait_exponential
from drako import with_langgraph_compliance


class AgentState(TypedDict):
    query: str
    result: str


# ok: SEC-001
api_key = os.environ.get("OPENAI_API_KEY", "")


# ok: BP-003
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def call_llm(prompt: str, timeout: int = 30) -> str:
    """LLM call with retry and timeout."""
    return "mock response"


def research_node(state: AgentState) -> AgentState:
    """Research node with proper type hints."""
    result = call_llm(state["query"])
    return {"query": state["query"], "result": result}


def review_node(state: AgentState) -> AgentState:
    """Review node with validation."""
    if not state.get("result"):
        raise ValueError("No result to review")
    return state


# Build graph
graph = StateGraph(AgentState)
graph.add_node("research", research_node)
graph.add_node("review", review_node)
graph.add_edge("research", "review")
graph.add_edge("review", END)
graph.set_entry_point("research")

compiled = graph.compile()

# ok: GOV-001
# ok: GOV-002
app = with_langgraph_compliance(compiled, config_path=".drako.yaml")
