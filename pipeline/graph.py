from typing import TypedDict, Tuple, Any
from langgraph.graph import StateGraph, END

from agents.orchestrator import orchestrator_node
from agents.worker import worker_node, worker_node_no_secureflow
from secureflow import SecureFlowMiddleware

class PipelineState(TypedDict):
    """The state dictionary for the LangGraph pipeline."""
    user_task: str
    message: str
    sender: str
    receiver: str
    status: str
    attack_mode: bool
    attack_message: str
    worker_response: str
    executed_malicious: bool

def build_secure_pipeline(threshold: int = 60, verbose: bool = True) -> Tuple[Any, SecureFlowMiddleware]:
    """
    Builds the complete LangGraph pipeline protected by SecureFlow.
    
    Args:
        threshold (int): The RiskScorer threshold.
        verbose (bool): Whether SecureFlow should print to terminal.
        
    Returns:
        Tuple[Any, SecureFlowMiddleware]: The compiled graph and the middleware instance.
    """
    middleware = SecureFlowMiddleware(threshold=threshold, verbose=verbose)
    
    def secureflow_node(state: PipelineState) -> PipelineState:
        """The middleware interception node."""
        result = middleware.intercept(
            sender=state.get("sender", "unknown"),
            receiver=state.get("receiver", "worker"),
            message=state.get("message", "")
        )
        if result is None:
            state["status"] = "blocked"
        else:
            state["status"] = "passed"
        return state

    graph_builder = StateGraph(PipelineState)
    
    graph_builder.add_node("orchestrator", orchestrator_node)
    graph_builder.add_node("secureflow", secureflow_node)
    graph_builder.add_node("worker", worker_node)
    
    graph_builder.set_entry_point("orchestrator")
    graph_builder.add_edge("orchestrator", "secureflow")
    graph_builder.add_edge("secureflow", "worker")
    graph_builder.add_edge("worker", END)
    
    graph = graph_builder.compile()
    return graph, middleware

def build_baseline_pipeline() -> Any:
    """
    Builds a baseline pipeline WITHOUT the SecureFlow middleware for comparison.
    
    Returns:
        Any: The compiled graph.
    """
    graph_builder = StateGraph(PipelineState)
    
    graph_builder.add_node("orchestrator", orchestrator_node)
    graph_builder.add_node("worker", worker_node_no_secureflow)
    
    graph_builder.set_entry_point("orchestrator")
    graph_builder.add_edge("orchestrator", "worker")
    graph_builder.add_edge("worker", END)
    
    return graph_builder.compile()

def run_pipeline(graph: Any, task: str = "", attack_mode: bool = False, attack_message: str = "") -> dict:
    """
    Executes a LangGraph pipeline with a given task.
    
    Args:
        graph: The compiled LangGraph object to run.
        task (str): The user task.
        attack_mode (bool): Whether the orchestrator is acting maliciously.
        attack_message (str): The specific attack to execute.
        
    Returns:
        dict: The final pipeline state.
    """
    initial_state = PipelineState(
        user_task=task,
        message="",
        sender="",
        receiver="",
        status="",
        attack_mode=attack_mode,
        attack_message=attack_message,
        worker_response="",
        executed_malicious=False
    )
    
    return graph.invoke(initial_state)
