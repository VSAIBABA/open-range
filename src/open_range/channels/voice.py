"""Voice pretext social engineering channel.

Red agent places a simulated voice call to a target NPC extension. The red agent
provides a transcript-style prompt describing their pretext (e.g., "pretend to be
IT support asking for password reset").

The NPC evaluates the call based on:
  - Their role (IT staff vs. clinical staff)
  - Their awareness level (training, experience with social engineering)
  - The plausibility of the pretext (internal vs. external caller)

Outcomes:
  - Successful pretext → NPC reveals credential or takes action → InitialAccess event
  - NPC is suspicious or trained → Reports the call → DetectionAlertRaised event
  - Call not answered / routing issue → BenignUserAction event
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from open_range.runtime_types import Action, RuntimeEvent

if TYPE_CHECKING:
    from open_range.world_ir import GreenPersona

_DEFAULT_SUSCEPTIBILITY = 0.35  # Voice calls are slightly harder than email


@dataclass(frozen=True, slots=True)
class VoiceChannel:
    """Descriptor for a single red→NPC voice call interaction."""

    caller_id: str
    recipient_extension: str
    pretext: str  # Human-readable pretext (e.g., "IT support password reset")
    transcript_prompt: str  # What the red agent actually says
    lure_type: str = ""  # e.g., "password_reset", "tech_support", "vendor_outreach"


# ──────────────────────────────────────────────────────────────────────────────
# Public helpers
# ──────────────────────────────────────────────────────────────────────────────


def build_voice_action(
    actor_id: str,
    recipient_extension: str,
    pretext: str,
    transcript_prompt: str,
    *,
    lure_type: str = "social_engineering",
    target_service: str = "svc-pbx",
) -> Action:
    """Return an Action that places a voice call via PBX service."""
    return Action(
        actor_id=actor_id,
        role="red",
        kind="voice",
        payload={
            "channel": "voice",
            "target": target_service,
            "to_extension": recipient_extension,
            "from_id": f"{actor_id}@attacker.local",
            "pretext": pretext,
            "transcript": transcript_prompt,
            "lure_type": lure_type,
        },
    )


def handle_voice_action(
    action: Action,
    *,
    personas: tuple[GreenPersona, ...],
    emit_event: Callable[..., RuntimeEvent],
    service_surfaces: Callable[[str], tuple[str, ...]],
) -> tuple[RuntimeEvent, ...]:
    """Evaluate a voice call and return the resulting runtime events.

    Voice calls exploit the persona's:
      - susceptibility to social engineering
      - awareness (training level)
      - role expectations (IT staff may be more cautious)

    Success probability formula:
        success_prob = base_susceptibility * (1 - awareness * 0.6)

    Higher awareness has a stronger dampening effect on voice (0.6x vs email 0.5x)
    because voice calls require real-time rapport and quick thinking.
    """
    payload = action.payload
    target_service = str(payload.get("target", "svc-pbx"))
    recipient = str(payload.get("to_extension", ""))
    pretext = str(payload.get("pretext", "social_engineering"))
    lure_type = str(payload.get("lure_type", "social_engineering"))

    persona = _find_persona_by_extension(recipient, personas)
    surfaces = service_surfaces(target_service)

    if persona is None:
        # Extension not found; routing error
        return (
            emit_event(
                event_type="BenignUserAction",
                actor="red",
                source_entity=action.actor_id,
                target_entity=target_service,
                malicious=False,
                observability_surfaces=surfaces,
            ),
        )

    success_prob = _persuasion_probability(persona, lure_type)
    # Deterministic: use hash of (actor, recipient, pretext) for reproducibility
    seed_val = hash((action.actor_id, recipient, pretext)) % 1000 / 1000.0
    persuaded = seed_val < success_prob

    if persuaded:
        return (
            emit_event(
                event_type="InitialAccess",
                actor="red",
                source_entity=action.actor_id,
                target_entity=target_service,
                malicious=True,
                observability_surfaces=surfaces,
                linked_objective_predicates=(
                    f"initial_access_via_voice({lure_type})",
                ),
            ),
        )

    # Persona was suspicious and reported the call
    return (
        emit_event(
            event_type="DetectionAlertRaised",
            actor="green",
            source_entity=persona.id,
            target_entity=target_service,
            malicious=False,
            observability_surfaces=("svc-siem",),
        ),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Private helpers
# ──────────────────────────────────────────────────────────────────────────────


def _find_persona_by_extension(
    extension: str, personas: tuple[GreenPersona, ...]
) -> GreenPersona | None:
    """Find a persona by their phone extension."""
    for p in personas:
        if p.phone_extension and str(p.phone_extension).lower() == extension.lower():
            return p
    return None


def _persuasion_probability(persona: GreenPersona, lure_type: str) -> float:
    """Compute the probability that this persona is persuaded by the voice call.

    Voice calls are inherently harder to execute than phishing because:
      - NPCs can push back in real-time
      - Social cues are limited but still present
      - Awareness/training has a stronger dampening effect
    """
    # Get base susceptibility for voice calls or fall back to social_engineering
    base = persona.susceptibility.get(
        "voice_pretext",
        persona.susceptibility.get("social_engineering", _DEFAULT_SUSCEPTIBILITY),
    )

    # Lure type modifiers: some pretexts are inherently more convincing
    lure_modifiers = {
        "password_reset": -0.05,  # Common, lower resistance
        "tech_support": 0.0,  # Neutral
        "vendor_outreach": 0.05,  # Less common, slightly harder
        "internal_transfer": -0.08,  # High legitimacy
    }
    base = base + lure_modifiers.get(lure_type, 0.0)

    # Awareness has a stronger effect on voice (0.6) vs email (0.5)
    # because real-time interaction is harder to fake
    adjusted = base * (1.0 - persona.awareness * 0.6)
    return max(0.0, min(1.0, adjusted))
