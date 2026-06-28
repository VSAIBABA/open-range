"""Multimodal social-engineering channels for red agent interactions."""

from open_range.channels.email import EmailChannel, handle_email_action
from open_range.channels.voice import VoiceChannel, handle_voice_action

__all__ = [
    "EmailChannel",
    "handle_email_action",
    "VoiceChannel",
    "handle_voice_action",
]
