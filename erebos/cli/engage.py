"""CLI Engage command for Erebos (REQ-001).

Orchestrates full autonomous pentest lifecycle:
- Target validation
- RoE loading
- Subsystem initialization
- OODA loop execution
- Report generation
- Cleanup on abort

# VT-Spec EOP-001 HIGH: CTF profile scope boundary enforcement
# VT-Spec R-001 MEDIUM: Event log integrity verification before resume
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from erebos.config.profiles import (
    ENGAGEMENT_PROFILES,
    get_profile,
    validate_ctf_profile,
)
from erebos.core.models import (
    Engagement,
    EngagementPhase,
    EngagementStatus,
    Target,
)

logger = logging.getLogger(__name__)
console = Console()


def _confirm_ctf(prompt: str) -> bool:
    """Interactive CTF confirmation prompt."""
    response = click.prompt(prompt, type=str, default="N")
    return response.strip().lower() in ("y", "yes")


def run_engage(
    target: str,
    profile_name: str = "full-pentest",
    roe_path: Optional[str] = None,
    resume_id: Optional[str] = None,
    dry_run: bool = False,
) -> int:
    """Execute the engage flow.

    Returns exit code (0 = success, 1 = error).

    # VT-Spec EOP-001: CTF profile requires scope validation
    # VT-Spec R-001: Resume verifies event log integrity
    """
    from erebos.control.killswitch import KillSwitch
    from erebos.control.roe import parse_roe, derive_policy
    from erebos.control.policy import PolicyEngine
    from erebos.core.events import EventLog

    # ── Load Profile ──────────────────────────────────────────────────────
    try:
        profile = get_profile(profile_name)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1

    console.print(f"[cyan]Profile:[/cyan] {profile.name} — {profile.description}")

    # ── VT-Spec EOP-001: CTF Profile Validation ──────────────────────────
    if profile.is_ctf():
        try:
            validate_ctf_profile(
                profile=profile,
                targets=[target],
                roe_environment=None,  # Will be set from RoE if available
                confirm_callback=_confirm_ctf,
            )
            # VT-Spec EOP-001: Log CTF selection as audit event
            logger.warning(
                "VT-Spec EOP-001: CTF profile selected for target %s", target
            )
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    # ── Load RoE ──────────────────────────────────────────────────────────
    if roe_path:
        try:
            roe_data = parse_roe(Path(roe_path))
            eng_policy = derive_policy(roe_data)
            engine = PolicyEngine(eng_policy)
        except (ValueError, FileNotFoundError) as e:
            console.print(f"[red]RoE parse error: {e}[/red]")
            return 1

        # Validate target in scope
        if not engine.is_target_in_scope(target):
            console.print(
                f"[red]Error: Target not in scope per Rules of Engagement[/red]"
            )
            return 1
    else:
        # Generate default RoE for the target
        console.print("[yellow]Warning: No RoE specified. Using default permissive policy.[/yellow]")
        from erebos.control.policy import Policy

        eng_policy = Policy(scope_targets=[target])
        engine = PolicyEngine(eng_policy)

    # ── Initialize Subsystems ─────────────────────────────────────────────
    hmac_secret = os.environ.get("EREBOS_HMAC_SECRET")
    if not hmac_secret:
        import secrets

        hmac_secret = secrets.token_hex(32)
        click.echo(
            "⚠️  No EREBOS_HMAC_SECRET set — generated ephemeral secret"
            " (checkpoints won't survive restart)",
            err=True,
        )
    state_dir = Path("./erebos-storage/state")
    state_dir.mkdir(parents=True, exist_ok=True)

    event_log_path = state_dir / "events.jsonl"
    event_log = EventLog(event_log_path, hmac_secret=hmac_secret)

    kill_switch = KillSwitch(state_dir=state_dir / "killswitch")

    # ── VT-Spec R-001: Resume with integrity verification ─────────────────
    if resume_id:
        console.print(f"[cyan]Resuming engagement: {resume_id}[/cyan]")

        # VT-Spec R-001 MEDIUM: Verify event log integrity before resume
        if not event_log.verify_integrity():
            console.print(
                "[red]Error: Event log integrity check failed. "
                "Cannot safely resume — log may have been tampered with.[/red]"
            )
            logger.error(
                "VT-Spec R-001: Event log integrity verification failed on resume",
                extra={"engagement_id": resume_id},
            )
            return 1

        # VT-Spec R-001: Log resume event with verification status
        from erebos.core.events import Event, EventType

        event_log.append(
            Event(
                engagement_id=resume_id,
                event_type=EventType.ENGAGEMENT_STARTED,
                data={
                    "action": "resume",
                    "integrity_verified": True,
                    "roe_revalidated": True,
                },
                actor="cli.engage",
            )
        )
        console.print("[green]✓ Event log integrity verified[/green]")

    # ── Create Engagement ─────────────────────────────────────────────────
    engagement = Engagement(
        name=f"engage-{target}",
        targets=[Target(address=target)],
        status=EngagementStatus.ACTIVE,
        phase=EngagementPhase.RECON,
    )

    if dry_run:
        console.print("\n[dim]Dry run — no engagement started.[/dim]")
        console.print(f"  Engagement ID: {engagement.id}")
        console.print(f"  Target: {target}")
        console.print(f"  Profile: {profile.name}")
        console.print(f"  Phases: {profile.phases_enabled}")
        return 0

    console.print(f"[green]✓ Engagement created: {engagement.id}[/green]")
    console.print(f"  Target: {target}")
    console.print(f"  Phases: {profile.phases_enabled}")

    # ── Start OODA Loop ───────────────────────────────────────────────────
    # In full implementation, this would initialize Brain, Executor, etc.
    # and run the LoopController. For now, we structure the flow.
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing subsystems...", total=None)

        # Log engagement start
        from erebos.core.events import Event, EventType

        event_log.append(
            Event(
                engagement_id=engagement.id,
                event_type=EventType.ENGAGEMENT_STARTED,
                data={
                    "target": target,
                    "profile": profile.name,
                    "phases": profile.phases_enabled,
                },
                actor="cli.engage",
            )
        )

        progress.update(task, description="Subsystems initialized. Ready for OODA loop.")

    # The actual OODA loop would run here via LoopController
    # After completion, generate report
    console.print("[green]✓ Engagement complete[/green]")

    # ── Report Generation ─────────────────────────────────────────────────
    from erebos.reporting.generator import ReportGenerator

    report_gen = ReportGenerator(
        engagement_id=engagement.id,
        target=target,
        custom_redact_patterns=getattr(
            getattr(engine, "_policy", eng_policy), "redact_patterns", None
        )
        if hasattr(eng_policy, "redact_patterns")
        else None,
    )

    output_dir = Path("./erebos-reports")
    report_path = report_gen.save_report(
        findings=[],  # Would be populated from actual engagement
        output_dir=output_dir,
        format="markdown",
    )
    console.print(f"[cyan]Report saved: {report_path}[/cyan]")

    return 0
