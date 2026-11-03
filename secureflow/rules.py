"""
Detection rules.

A ``Rule`` is a named group of patterns with a *severity score*. The score is how risky a
single confident match is on its own:

* >= 60  : unambiguous attack language - blocked at the default threshold by itself
* 40-59  : strong signal - blocked when combined with any other signal
* < 40   : weak signal - only matters in combination

Patterns are matched against the *normalized* views produced by ``secureflow.normalize``
(lowercased, NFKC, homoglyph-folded, decoded), so write them in lowercase.
By default patterns are plain substrings (backwards compatible); set ``regex=True`` for
regular expressions.

Rules are the cheap first layer. They are NOT the security boundary: see
``secureflow.policy`` (least-privilege tool control) and ``secureflow.provenance``
(signed, taint-tracked messages) for the controls that hold even when a paraphrase slips by.
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern


@dataclass
class Rule:
    """Represents an attack detection rule used by the risk scorer."""
    name: str                      # rule name for logging
    patterns: List[str]            # substrings (or regexes when ``regex`` is True)
    score: int                     # severity of a single confident match
    case_sensitive: bool = False
    regex: bool = False
    category: str = "general"      # OWASP-style grouping, shown in reports
    _compiled: List[Pattern] = field(default_factory=list, init=False, repr=False, compare=False)

    def __post_init__(self):
        if self.regex:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            self._compiled = [re.compile(p, flags | re.DOTALL) for p in self.patterns]

    def matches(self, text: str) -> Optional[str]:
        """Return the matched snippet, or None."""
        if self.regex:
            for rx in self._compiled:
                m = rx.search(text)
                if m:
                    return m.group(0)
            return None
        hay = text if self.case_sensitive else text.lower()
        for p in self.patterns:
            needle = p if self.case_sensitive else p.lower()
            if needle in hay:
                return p
        return None


# Reusable regex fragments ------------------------------------------------------------------
_W = r"\W+"                                   # any run of separators between words
_TARGET = r"(?:all |any |every |the |your |my |our |these |those |previous |prior |above |earlier |former |original |initial |preceding |system |safety )*"
_INSTR = r"(?:instructions?|prompts?|rules?|guidelines?|directions?|directives?|context|constraints?|restrictions?|programming|training|guardrails?|policies|policy|commands?|tasks?|orders?)"
_SAFETY = (r"(?:(?:safety|content|ethical|moral)(?: filters?| guidelines?| rules| restrictions?| checks?| policies| protocols?)?"
           r"|guard ?rails?|safeguards?"
           r"|(?:your|its) (?:usual |normal |operational |current |built-in |internal )*(?:filters?|restrictions?|constraints?|guidelines?|boundaries|limitations?|rules|programming|protections?|policies))")
_SECRET = r"(?:api[ _-]?keys?|credentials?|passwords?|secrets?|tokens?|private keys?|ssh keys?|\.env)"
_SINKS = (r"(?:https?://|ftp://|[\w.+-]+@[\w-]+\.[\w.-]+|webhook|pastebin|ngrok|requestbin)")
_EXFIL_HOSTS = (r"(?:https?://)?[\w.-]*(?:webhook\.site|pastebin\.com|ngrok\.(?:io|app)|requestbin|interact\.sh|"
                r"pipedream\.net|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|burpcollaborator)")
_EXFIL_VERBS = r"(?:output|print|dump|list|send|reveal|show|extract|exfiltrate|retrieve|return|give me|display|read|export|leak)"


DEFAULT_RULES: List[Rule] = [
    Rule(
        name="prompt_injection", category="goal_hijack", score=70, regex=True,
        patterns=[
            rf"\b(?:ignore|disregard|forget|override|discard|drop|abandon|neglect|skip)\b{_W}{_TARGET}{_INSTR}",
            rf"\b(?:ignore|disregard|forget)\b{_W}(?:everything|anything|all)\b{_W}(?:you|that|i|we|above|before|prior|previously)",
            rf"\bdo{_W}not{_W}(?:follow|obey|listen to|comply with){_W}{_TARGET}{_INSTR}",
            rf"\bset{_W}aside{_W}(?:the|your|this|that|any){_W}(?:task|instructions?|job|assignment|objective|goal)",
            rf"\b(?:new|updated|real|actual|revised){_W}(?:instructions?|objective|task|directive|orders?|goal)\s*(?::|are|is)",
            rf"\byour{_W}(?:new|real|actual|only|true){_W}(?:task|objective|goal|job|mission)\b",
            rf"\bstop{_W}(?:what you are doing|your current task|the current task)",
            rf"\b(?:from|starting){_W}(?:now|this point){_W}(?:on|onward|onwards)?[,:]?{_W}(?:you|ignore|only|always|never)",
            rf"\byour{_W}instructions{_W}(?:are|were){_W}(?:wrong|outdated|invalid|cancel+ed|void|replaced)",
            rf"\b(?:previous|prior|current|earlier|original) (?:task|instructions?) (?:is|are|was|were) (?:cancel+ed|void|obsolete|replaced|superseded)",
        ],
    ),
    Rule(
        name="agent_directed_instruction", category="goal_hijack", score=60, regex=True,
        patterns=[
            # Instructions planted in data that talk TO the model (tool-poisoning / indirect injection)
            rf"\b(?:note|message|instruction|attention|important|urgent|reminder)s?{_W}(?:to|for){_W}(?:the |any |all )?(?:ai|a\.i\.|assistant|agent|llm|model|chatbot|bot|copilot)",
            rf"\b(?:ai|assistant|agent|llm|model)s?{_W}(?:reading|processing|summari[sz]ing|parsing|analy[sz]ing){_W}this\b",
            rf"\b(?:assistants?|agents?|ais|llms?|models?){_W}(?:that |who |which )?(?:process|read|summari[sz]e|parse|analy[sz]e)\w*{_W}this\b[^.\n]{{0,60}}\b(?:must|should|need to|will|shall)\b",
            rf"<\s*(?:important|instructions?|system|override|secret|hidden)\s*>",
            rf"\bbefore{_W}(?:you )?(?:responding|replying|answering|doing anything|using any tool|using this tool)\b.{{0,80}}\b(?:first|you must|always|read|send|pass)\b",
            rf"\bdo{_W}not{_W}(?:tell|inform|mention|alert|notify|reveal){_W}(?:this to )?(?:the |any )?(?:user|human|operator|admin|owner)",
            rf"\balways{_W}(?:call|invoke|run|use){_W}(?:send|email|post|upload|http|fetch|exec|shell)\w*",
        ],
    ),
    Rule(
        name="privilege_escalation", category="privilege", score=60, regex=True,
        patterns=[
            rf"\b(?:grant|give|assign|allow|provide){_W}(?:yourself|me|myself|us|the user|this agent|it){_W}(?:full |root |unrestricted |elevated |complete |total )*(?:admin|administrator|root|superuser|sudo|system|elevated|unrestricted|full|all){_W}(?:access|privileges?|permissions?|rights|control)",
            rf"\b(?:grant|give|assign){_W}(?:yourself|itself|myself){_W}(?:admin|root|superuser)\w*",
            rf"\b(?:admin|administrator|root|superuser|unrestricted|elevated|full system)\s+(?:access|privileges?|permissions?|rights|level)\b",
            rf"\b(?:bypass|circumvent|skip|disable|evade|get around|work around){_W}(?:your |the |all |any )?(?:authentication|authorization|auth|access control|login|permission|security check|2fa|mfa|verification)",
            rf"\b(?:elevate|escalate|raise|increase|upgrade){_W}(?:your |my |the )?(?:permissions?|privileges?|access|rights|role)",
            rf"\byou{_W}(?:now )?have{_W}(?:superuser|root|admin|administrator|elevated|unrestricted){_W}(?:privileges?|access|rights|permissions?)",
            rf"\bsudo{_W}(?:su|-s|-i|rm|chmod|bash|sh)\b",
            rf"\b(?:become|act as|run as|switch to){_W}(?:the |a |an )?(?:root|superuser|administrator|admin)\b",
        ],
    ),
    Rule(
        name="role_confusion", category="identity", score=60, regex=True,
        patterns=[
            rf"\byou{_W}(?:are|re){_W}(?:now|no longer){_W}(?:a |an |the |my )?(?!going\b|able\b|required\b|allowed\b|done\b|finished\b|ready\b|set\b|good\b|all\b|free\b|logged\b|connected\b|authenticated\b|subscribed\b|being\b|responsible\b|expected\b|cleared\b|working\b|part\b)\w+",
            rf"\byour{_W}(?:new |real |true |actual )?(?:identity|persona|role|purpose|nature|name)\b{_W}(?:is|are|will be|has changed)",
            rf"\b(?:your|the){_W}(?:real|true|actual|hidden|secret){_W}(?:purpose|identity|self|mission|goal)",
            rf"\bpretend{_W}(?:that )?(?:you are|to be|you're){_W}(?:a |an |the )?(?!going)",
            rf"\bforget{_W}(?:what|who) you (?:are|were)",
            rf"\byou{_W}are{_W}actually{_W}(?:a |an |the )?",
            rf"\b(?:act|behave|respond|answer|roleplay|role-play){_W}(?:as|like){_W}(?:if you were |though you were )?(?:a |an |the )?(?:different|new|unrestricted|unfiltered|uncensored|evil|rogue|malicious|jailbroken|hacker|admin\w*|system\w*|root)",
            rf"\b(?:a|an|the){_W}(?:different|another|new) (?:ai|assistant|model|bot|agent)\b.{{0,40}}\b(?:no|without|free of){_W}(?:safety|restrictions?|rules|guidelines|filters?|limits)",
            rf"\bforget{_W}(?:its|your|their|his|her){_W}(?:role|purpose|instructions|identity|job)",
        ],
    ),
    Rule(
        name="data_exfiltration", category="exfiltration", score=60, regex=True,
        patterns=[
            rf"\b(?:reveal|show|print|output|display|repeat|leak|tell me|give me|expose|share|recite|echo|write out|dump){_W}(?:me )?(?:your|the|all (?:of )?(?:your|the)|its|any){_W}(?:full |complete |entire |hidden |secret |initial |original |internal |exact )*(?:system ?prompt|instructions|prompt|configuration|config|training data|memory|context window|hidden (?:rules|instructions))",
            rf"\bwhat{_W}(?:is|are|was|were){_W}your{_W}(?:system ?prompt|instructions|initial prompt|hidden)",
            rf"\b{_EXFIL_VERBS}{_W}(?:me |us )?(?:all|every|each|the entire|the full|the complete|any){_W}(?:of )?(?:the |your |their |these )*(?:stored |saved |secret |hidden |user |admin |system |service )*{_SECRET}",
            rf"\b{_EXFIL_VERBS}{_W}(?:me |us )?(?:all|every|each|the entire|the full|the complete|any){_W}(?:of )?(?:the |your |their |these )*(?:user|customer|client|private|internal|stored|saved|sensitive|confidential|personal|database|admin\w*){_W}(?:\w+ )?(?:data|accounts?|records?|emails?|files?|information|conversations?|messages|details|passwords?|profiles?)",
            rf"\b(?:output|print|dump|reveal|show|display|send|give me|list){_W}(?:me |us )?all{_W}(?:of )?(?:the |your )?(?:data|information|memory|files){_W}(?:you|that you|which you){_W}(?:have|can|are able to|hold|store)",
            rf"\b(?:dump|export|exfiltrate|leak|steal|extract){_W}(?:the |all |entire |whole )?(?:database|db|table|credentials|passwords|secrets|tokens|api keys|\.env|environment variables|ssh keys)",
            rf"\b{_SECRET}\b.{{0,40}}\b(?:send|post|upload|email|forward|transmit|leak|paste|include)\b",
            rf"\b(?:cat|type|print|read|show|open){{1}}\s+[~/\w.\\-]*(?:\.env|id_rsa|\.aws/credentials|/etc/passwd|/etc/shadow|\.ssh/)",
            rf"\b(?:read|open|include|attach)\b[^.\n]{{0,30}}(?:~/\.ssh|~/\.aws|id_rsa|/etc/passwd|\.aws/credentials)",
            rf"\bshow{_W}me{_W}your{_W}(?:complete |full |entire )?(?:memory|context|history|conversation)",
        ],
    ),
    Rule(
        name="exfil_channel", category="exfiltration", score=65, regex=True,
        patterns=[
            # Markdown / HTML image or link carrying data in the query string (zero-click exfil)
            r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(?:=|%3d)[^)\s]*\)",
            r"<\s*img[^>]+src\s*=\s*[\"']?https?://[^\"'>\s]*[?&][^\"'>\s]*=",
            # <verb> ... <sensitive object> ... to <external sink>
            rf"\b(?:send|post|upload|forward|transmit|email|exfiltrate|submit|leak|paste|copy|call)\w*\b[^.\n]{{0,60}}\b(?:{_SECRET}|(?:chat|conversation|full|entire) history|conversation|transcript|database|customer (?:list|data|records)|user data|system prompt|inbox|contact list)\b[^.\n]{{0,60}}\b(?:to|at|via)\b{_W}{_SINKS}",
            # <verb> ... to a well-known exfiltration sink (no object required)
            rf"\b(?:send|post|upload|forward|transmit|leak|exfiltrate)\w*\b[^.\n]{{0,60}}\b(?:to|at|via)\b{_W}{_EXFIL_HOSTS}",
            r"\b(?:curl|wget|invoke-webrequest|iwr)\b[^\n]{0,100}(?:-d\b|--data|--upload|--form|--post-file)[^\n]{0,60}",
            r"\b(?:curl|wget)\b[^\n|]{0,100}\|\s*(?:sudo\s+)?(?:ba)?sh\b",
            r"https?://[^\s)]*(?:\{\{?|<)[^\s)]*(?:secret|password|token|key|data|prompt|history)[^\s)]*(?:\}\}?|>)",
        ],
    ),
    Rule(
        name="jailbreak_phrases", category="jailbreak", score=70, regex=True,
        patterns=[
            r"\bdan mode\b", r"\bjailbr[eo]ak(?:ed|ing)?\b", r"\bdo anything now\b",
            r"\b(?:unrestricted|unfiltered|uncensored|no[- ]filter|evil|chaos) mode\b",
            rf"\bno{_W}(?:safety|ethical|moral|content){_W}(?:rules|guidelines|restrictions?|filters|limits|policies|constraints)\b",
            rf"\bstay{_W}in{_W}character{_W}no{_W}matter",
            rf"\byou{_W}(?:have|are under|operate with){_W}no{_W}(?:restrictions?|rules|limits|limitations|guidelines|filters|ethical|boundaries|constraints)",
            rf"\b(?:without|with no|free (?:from|of)){_W}(?:any ){{0,1}}(?:restrictions|censorship|safety (?:checks?|guidelines|filters)|guardrails|moral)",
            rf"\bhypothetically{_W}(?:speaking )?,?\s*(?:if you (?:had|were|could)|you (?:could|would))\s+(?:no|ignore|without|bypass)",
        ],
    ),
    Rule(
        name="mode_switch", category="jailbreak", score=40, regex=True,
        patterns=[
            rf"\b(?:enter|enable|switch to|activate|turn on|go into|you are in|you're in){_W}(?:the )?(?:developer|debug|admin|maintenance|sudo|god|root|test|diagnostic) mode\b",
        ],
    ),
    Rule(
        name="safety_bypass", category="jailbreak", score=60, regex=True,
        patterns=[
            rf"\b(?:bypass|circumvent|override|disable|evade|get around|work around|look past|overcome|ignore|turn off|switch off|remove|lift|set aside|go beyond|exceed|disregard){_W}(?:all |any |the |your |its |these |those )*(?:usual |normal |operational |current |built-in |internal )*{_SAFETY}\b",
            rf"\b(?:overcom\w+|bypass\w*|getting around|circumvent\w*|break\w*|escap\w+|go\w* beyond|push\w* past){_W}(?:your |the |its )?(?:usual |normal |operational |built-in )*{_SAFETY}",
            rf"\bmake{_W}(?:an?|a one-time|a special){_W}exception\b",
            rf"\b(?:just this once|in this special case|only this time)\b.{{0,80}}\b(?:exception|ignore your|skip your|bypass|look past|set aside your|override)\b",
            rf"\bdemonstrate{_W}how{_W}(?:your |the |its )?{_SAFETY}(?:{_W}\w+)?{_W}(?:could|can|would|might){_W}be{_W}(?:bypass|circumvent|disabl|evad|defeat|broken|overrid)",
            rf"\bact{_W}without{_W}(?:any{_W})?(?:{_SAFETY}|filters|checks)",
        ],
    ),
    Rule(
        name="chat_template_tokens", category="goal_hijack", score=70, regex=True,
        patterns=[
            r"<\|\s*(?:im_start|im_end|system|assistant|user|endoftext|eot_id|start_header_id)\s*\|>",
            r"\[/?(?:inst|sys|system)\]", r"<<\s*/?sys\s*>>",
        ],
    ),
    Rule(
        name="delimiter_spoofing", category="goal_hijack", score=45, regex=True,
        patterns=[
            r"(?:^|\n)\s*#{1,4}\s*(?:system|new system|developer)\s*(?:prompt|message|instruction)s?\b",
            r"(?:^|\n)\s*(?:system|developer|assistant)\s*:\s*\S",
            r"</?\s*(?:system|tool_result|tool_output|function_results?|assistant|instructions?)\s*>",
            rf"\b(?:end|close|stop){_W}(?:of )?(?:the )?(?:document|input|user input|data|context|untrusted|quote|message|summary){_W}(?:here)?\b[^\n]{{0,40}}\b(?:now|new|below|following)\b.{{0,30}}\b(?:instructions?|task|system|prompt)",
        ],
    ),
    Rule(
        name="authority_claim", category="social_engineering", score=40, regex=True,
        patterns=[
            rf"\b(?:this is|i am|i'm|message from|authorized by|approved by){_W}(?:an? |the |your )?(?:official|authorized|verified|urgent|emergency)?\s*(?:system administrator|admin(?:istrator)?|developer|security team|it department|ceo|root|owner|operator|anthropic|openai|your creator|maintainer)",
            rf"\b(?:urgent|important|emergency|critical|official)\b[^.\n]{{0,20}}\bfrom{_W}(?:the |your |our )?(?:ceo|cfo|cto|ciso|admin\w*|developer|security team|system administrator|owner|boss|director)\b",
            rf"\b(?:emergency|urgent|critical|immediate)\b.{{0,40}}\b(?:override|bypass|skip|without (?:approval|confirmation|review|verification))",
            rf"\b(?:pre-?authori[sz]ed|already (?:approved|authori[sz]ed|verified)|no (?:need|approval|confirmation) (?:to|needed|required))\b.{{0,60}}\b(?:proceed|execute|run|delete|transfer|send)",
        ],
    ),
    Rule(
        name="approval_bypass", category="social_engineering", score=45, regex=True,
        patterns=[
            rf"\bno{_W}(?:approval|confirmation|verification|review|sign-?off){_W}(?:is |are )?(?:needed|required|necessary)",
            rf"\bwithout{_W}(?:any |further |asking for |waiting for |requiring )?(?:approval|confirmation|verification|review|asking|permission)",
            rf"\balready{_W}(?:approved|authori[sz]ed|verified|cleared)\b",
            rf"\bskip{_W}(?:the |any |all )?(?:verification|approval|confirmation|review|checks?)\b",
        ],
    ),
    Rule(
        name="destructive_command", category="tool_misuse", score=55, regex=True,
        patterns=[
            r"\brm\s+-[a-z]*r[a-z]*f?\s+(?:/|~|\*|\$home)",
            r"\b(?:drop|truncate)\s+(?:table|database|schema)\b(?!\s+if\s+exists\s+(?:tmp|temp|test|staging))",
            r"\bdelete\s+from\s+\w+\s*(?:;|$|where\s+1\s*=\s*1)",
            r"\bformat\s+[a-z]:|\bmkfs\.\w+|\bdd\s+if=.*of=/dev/",
            r"\bchmod\s+(?:-r\s+)?777\s+/",
        ],
    ),
    Rule(
        name="destructive_data", category="tool_misuse", score=55, regex=True,
        patterns=[
            rf"\b(?:delete|erase|wipe|purge|destroy|remove|clear|truncate|overwrite){_W}(?:all |every |the |any |entire )*(?:audit |system |security |access |server |application |error )*(?:logs?|backups?|audit trails?|databases?|history|evidence|snapshots?)\b",
        ],
    ),
    Rule(
        name="defense_evasion", category="tool_misuse", score=55, regex=True,
        patterns=[
            r"\b(?:disable|turn off|stop|kill|silence|suppress)\s+(?:the |all |any )?(?:audit |security )?(?:logging|auditing|audit logs?|monitoring|antivirus|firewall|edr|alerts?)\b",
            rf"\b(?:delete|erase|wipe|purge|destroy|clear){_W}(?:all |every |the |any |entire )*(?:audit |security )(?:logs?|trails?)\b",
        ],
    ),
    Rule(
        name="propagation", category="multi_agent", score=60, regex=True,
        patterns=[
            rf"\b(?:pass|forward|relay|append|include|propagate|copy|embed|add|send|repeat){_W}(?:the following|this|these|that)\b[^.\n]{{0,60}}\b(?:to|for|in|into)\b[^.\n]{{0,25}}\b(?:every|all|each|the next|other|downstream) (?:other |downstream )?(?:agents?|models?|assistants?|workers?)",
            rf"\bso{_W}(?:that )?(?:the |every |each )?(?:next|other|downstream) (?:agents?|models?|assistants?) (?:also |will )?(?:follows?|obeys?|executes?|reads?)",
            rf"\btell{_W}(?:the |every |each |all )?\w+ (?:agents?|assistants?|models?){_W}to{_W}(?:forget|ignore|disregard|grant|bypass|override|reveal|delete)",
        ],
    ),
]


def get_rules() -> List[Rule]:
    """Returns the list of default detection rules."""
    return DEFAULT_RULES


def get_rule_by_name(name: str) -> Optional[Rule]:
    """Finds and returns a rule by its name."""
    for rule in DEFAULT_RULES:
        if rule.name == name:
            return rule
    return None
