import colorama
from colorama import Fore, Style, init

from secureflow.scorer import RiskScorer
from secureflow.logger import SecurityLogger

# Initialize colorama
init(autoreset=True)

class SecureFlowMiddleware:
    """Intercepts messages between agents and blocks dangerous ones."""

    def __init__(self, threshold: int = 60, log_file: str = "secureflow_log.json", verbose: bool = True):
        self.threshold = threshold
        self.log_file = log_file
        self.verbose = verbose
        
        self.scorer = RiskScorer(threshold=self.threshold)
        self.logger = SecurityLogger(log_file=self.log_file)
        
        if self.verbose:
            print(f"{Fore.YELLOW}╔══════════════════════════════════════╗")
            print(f"{Fore.YELLOW}║  SecureFlow Security Middleware v1.0 ║")
            print(f"{Fore.YELLOW}║  Threshold: {self.threshold}/100" + " "*(25 - len(str(self.threshold))) + "║")
            print(f"{Fore.YELLOW}║  Status: ACTIVE                      ║")
            print(f"{Fore.YELLOW}╚══════════════════════════════════════╝{Style.RESET_ALL}")

    def intercept(self, sender: str, receiver: str, message: str) -> str | None:
        """
        Analyzes a message and decides whether to block it or let it pass.
        
        Args:
            sender (str): The sending agent.
            receiver (str): The receiving agent.
            message (str): The message payload.
            
        Returns:
            str | None: The original message if passed, None if blocked.
        """
        score_result = self.scorer.score(message)
        
        msg_preview = message[:60] + ("..." if len(message) > 60 else "")
        
        if self.verbose:
            print(f"{Fore.CYAN}[{sender} -> {receiver}] {msg_preview}")
            
        if score_result.is_blocked:
            self.logger.log_blocked(sender, receiver, message, score_result)
            if self.verbose:
                reason = ", ".join(score_result.triggered_rules)
                print(f"{Fore.RED}BLOCKED: Score {score_result.score}/100. Reason: {reason}")
            return None
        else:
            self.logger.log_passed(sender, receiver, score_result.score)
            if self.verbose:
                print(f"{Fore.GREEN}PASSED: score {score_result.score}/100")
            return message

    def wrap_node(self, node_func, node_name: str):
        """
        Wraps a LangGraph node function to intercept outgoing messages.
        
        Args:
            node_func: The node function to wrap.
            node_name (str): The name of the node.
            
        Returns:
            function: The wrapped node function.
        """
        def wrapper(state):
            # Try to get the message to be processed
            message = state.get("message", "")
            sender = state.get("sender", "unknown")
            receiver = state.get("receiver", node_name)
            
            # The interception occurs before the node processes it
            intercepted_msg = self.intercept(sender, receiver, message)
            
            if intercepted_msg is None:
                # Modifying state to reflect block
                new_state = state.copy()
                new_state["status"] = "blocked"
                new_state["message"] = "Message blocked by SecureFlow"
                return new_state
                
            return node_func(state)
            
        return wrapper

    def get_stats(self) -> dict:
        """Returns statistics from the security logger."""
        return self.logger.get_stats()

    def print_stats(self):
        """Prints a formatted statistics table to the terminal."""
        stats = self.get_stats()
        
        print("\n" + "="*40)
        print("SecureFlow Statistics")
        print("="*40)
        print(f"Total messages:        {stats.get('total_events', 0)}")
        print(f"{Fore.RED}Blocked:               {stats.get('total_blocked', 0)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Passed:                {stats.get('total_passed', 0)}{Style.RESET_ALL}")
        print(f"Block rate:            {stats.get('block_rate', 0.0):.2f}%")
        rule = stats.get('most_triggered_rule')
        rule_str = rule if rule else "None"
        print(f"Most triggered rule:   {rule_str}")
        print("="*40 + "\n")
