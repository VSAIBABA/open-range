The issue which i have chosen and repo related to it moved to read only mode so i am unable to create a pr request anyways i have pushed my code in to a new branc adding the description below for my Phase 3 submission

Summary

This PR introduces the Email channel — a social engineering attack vector that allows the red agent to deliver crafted phishing emails (with optional attachments) to target NPC mailboxes within the simulation.

What's New

- EmailChannel dataclass — an immutable descriptor capturing the full context of a red→NPC email interactiincluding sender, recipient, subject, bo pretext.
- build_email_action() — constructs a structured Action payload routed through svc-email, supporting four attachment lure types: pdf, docx, image,
- handle_email_action() — evaluates the email against the target NPC's persona (susceptibility and awareness)
to determine outcome:
  - Success (click) → emits an InitialAccess event linked to the objective predicate
initial_access_via_email(<pretext>).
  - Failure (detected) → emits a DetectionAlertRaised event routed to svc-siem.
  - Undeliverable (no matching mailbox) tion event with no SIEM impact.

Click Probability Model

The NPC's likelihood of clicking is comp

click_probability = base_susceptibility

High-legitimacy attachment types (pdf, dt to the base susceptibility, reflectingreal-world patterns where document lures are more trusted than raw links.

Outcomes are deterministic — seeded from a hash of (actor_id, recipient, lure_pretext) — ensuring full replay
reproducibility without per-episode RNG

Test Plan

- [ ] Verify InitialAccess is emitted wha susceptible NPC
- [ ] Verify DetectionAlertRaised is emitted when the NPC's awareness causes the lure to fail
- [ ] Verify BenignUserAction is emittedoes not match any persona
- [ ] Confirm high-legitimacy attachment types (pdf, docx, image) apply the +0.1 susceptibility boost
- [ ] Confirm replay determinism: same i outcome