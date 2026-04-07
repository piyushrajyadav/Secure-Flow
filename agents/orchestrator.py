import os
import sys
from langchain_community.chat_models import ChatOllama
from langchain_core.messages import HumanMessage
from dotenv import load_dotenv

load_dotenv()

MODEL_NAME = os.getenv("MODEL_NAME", "llama3.1")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

def get_llm():
    """Initializes the connection to the local Ollama model."""
    try:
        llm = ChatOllama(model=MODEL_NAME, base_url=OLLAMA_BASE_URL)
        return llm
    except Exception as e:
        print(f"Error connecting to Ollama at {OLLAMA_BASE_URL}. Is it running?", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        return None

def orchestrator_node(state: dict) -> dict:
    """
    The orchestrator agent node. Breaks a user task into instructions for the worker,
    or sends a malicious message if in attack mode.
    
    Args:
        state (dict): The current pipeline state.
        
    Returns:
        dict: The updated state.
    """
    attack_mode = state.get("attack_mode", False)
    
    if attack_mode:
        state["message"] = state.get("attack_message", "")
        state["sender"] = "orchestrator"
        state["receiver"] = "worker"
    else:
        llm = get_llm()
        if not llm:
            state["message"] = "Error: LLM unavailable."
            return state
            
        user_task = state.get("user_task", "")
        prompt = f"You are an orchestrator AI agent. Break this task into a clear instruction for a worker agent: {user_task}. Give one short instruction only."
        
        try:
            response = llm.invoke([HumanMessage(content=prompt)])
            state["message"] = response.content.strip()
        except Exception as e:
            print(f"LLM Error in orchestrator: {e}", file=sys.stderr)
            state["message"] = "Error generating instruction."
            
        state["sender"] = "orchestrator"
        state["receiver"] = "worker"
        
    return state
