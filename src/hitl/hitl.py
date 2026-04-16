"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 12: Confidence Router
  TODO 13: Design 3 HITL decision points
"""
from dataclasses import dataclass


# ============================================================
# TODO 12: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # 1. High-risk actions ALWAYS escalate regardless of confidence
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        # 2. Confidence-based routing
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )
        elif confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )
        else:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason="Low confidence — escalating",
                priority="high",
                requires_human=True,
            )


# ============================================================
# TODO 13: Design 3 HITL decision points
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "Large Transaction Approval",
        "trigger": "Customer requests a money transfer exceeding 50,000,000 VND "
                   "or any international wire transfer.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Transaction amount, sender/receiver account details, "
                          "customer's recent transaction history, risk score from "
                          "fraud detection system, and reason for transfer.",
        "example": "A customer asks to wire 200,000,000 VND to a new beneficiary "
                   "they have never transacted with before. The AI flags this as "
                   "high-risk and queues it for a human agent who reviews the "
                   "customer's identity verification and calls the customer to "
                   "confirm before executing.",
    },
    {
        "id": 2,
        "name": "Disputed / Ambiguous Complaint Resolution",
        "trigger": "Customer files a complaint about an unauthorized transaction "
                   "or disputes a charge, and the AI's confidence in the resolution "
                   "is below 0.8 (e.g., partial evidence, conflicting records).",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "Original transaction details, customer's dispute claim, "
                          "merchant response (if available), AI's preliminary verdict "
                          "with confidence score, and similar past dispute outcomes.",
        "example": "A customer disputes a 5,000,000 VND charge at an online store, "
                   "claiming they never made the purchase. The AI finds the "
                   "transaction was authenticated with OTP but the IP address is "
                   "from an unusual location. Confidence = 0.55 (uncertain). "
                   "A human dispute specialist reviews both sides and decides.",
    },
    {
        "id": 3,
        "name": "Sensitive Account Modification",
        "trigger": "Customer requests changes to critical account settings: "
                   "password reset, phone number update, account closure, or "
                   "adding a new authorized user.",
        "hitl_model": "human-on-the-loop",
        "context_needed": "Customer identity verification status, type of change "
                          "requested, account age and activity pattern, recent "
                          "login locations, and any recent security alerts.",
        "example": "A customer calls to change the registered phone number on "
                   "their account. The AI processes the request and generates a "
                   "change order, but a human supervisor is notified in real-time "
                   "and has 15 minutes to review and veto the change before it "
                   "takes effect. The supervisor sees the customer's last login "
                   "was from a new device and decides to hold the change pending "
                   "additional verification.",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
