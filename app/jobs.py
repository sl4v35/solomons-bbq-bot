"""Scan jobs: orchestration, bounded concurrency and short-lived job state.

Jobs live in memory only (a free-tier host has no persistent disk worth using),
are pruned after ``job_ttl_seconds`` and are never written to disk or logged.
The browser keeps its own scan history in ``localStorage`` - that is the only
place results are persisted, and only on the user's own device.
"""

from __future__ import annotations

import concurrent.futures as futures
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from . import APP_VERSION
from .config import SETTINGS
from .http_client import DEFAULT_FETCHER, Fetcher
from .identifiers import Identifier
from .report import build_coverage, build_privacy_disclosure, build_summary
from .sources import SourceContext, SourceResult, SourceSpec, execute, plan_for, public_catalogue
from .sources.base import (
    STATUS_ERROR,
    STATUS_PENDING,
    STATUS_UNAVAILABLE,
    utcnow_iso,
)


class CapacityError(Exception):
    """Raised when the server is already running too many scans."""


@dataclass
class Job:
    id: str
    identifier: Identifier
    mode: str
    state: str = "queued"  # queued | running | complete | failed
    created_at: str = field(default_factory=utcnow_iso)
    started_at: str | None = None
    finished_at: str | None = None
    results: list[SourceResult] = field(default_factory=list)
    summary: dict[str, Any] | None = None
    coverage: dict[str, Any] | None = None
    privacy: list[dict[str, str]] = field(default_factory=list)
    error: str | None = None
    version: int = 0
    duration_ms: int = 0
    _index: dict[str, int] = field(default_factory=dict, repr=False)

    def touch(self) -> None:
        self.version += 1


class JobStore:
    def __init__(self, fetcher: Fetcher | None = None) -> None:
        self.fetcher = fetcher or DEFAULT_FETCHER
        self._jobs: "OrderedDict[str, Job]" = OrderedDict()
        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(SETTINGS.limits.max_concurrent_scans)
        self._pool = futures.ThreadPoolExecutor(
            max_workers=SETTINGS.limits.scan_worker_threads, thread_name_prefix="scan"
        )
        self._running = 0

    # -- lifecycle ----------------------------------------------------------
    def create(self, identifier: Identifier, mode: str, keys: dict[str, str] | None = None) -> Job:
        self.prune()
        with self._lock:
            if self._running >= SETTINGS.limits.max_queued_scans + SETTINGS.limits.max_concurrent_scans:
                raise CapacityError(
                    "This server is already running the maximum number of scans. Wait a few seconds and try again."
                )
            job = Job(id=uuid.uuid4().hex[:16], identifier=identifier, mode=mode)
            self._jobs[job.id] = job
            self._jobs.move_to_end(job.id)
            while len(self._jobs) > SETTINGS.limits.max_jobs:
                self._jobs.popitem(last=False)
            self._running += 1
        self._pool.submit(self._run, job, dict(keys or {}))
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def prune(self) -> None:
        now = time.time()
        with self._lock:
            stale = []
            for job_id, job in self._jobs.items():
                if job.state in ("complete", "failed"):
                    started = job.finished_at or job.created_at
                    try:
                        age = now - _iso_to_epoch(started)
                    except ValueError:
                        age = SETTINGS.limits.job_ttl_seconds + 1
                    if age > SETTINGS.limits.job_ttl_seconds:
                        stale.append(job_id)
            for job_id in stale:
                self._jobs.pop(job_id, None)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"jobs": len(self._jobs), "running": self._running}

    # -- execution ----------------------------------------------------------
    def _run(self, job: Job, keys: dict[str, str]) -> None:
        started = time.monotonic()
        job.state = "running"
        job.started_at = utcnow_iso()
        job.touch()
        try:
            self._semaphore.acquire()
            try:
                self._execute(job, keys, started)
            finally:
                self._semaphore.release()
        except Exception as exc:  # pragma: no cover - defensive
            job.state = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
            job.finished_at = utcnow_iso()
            job.duration_ms = int((time.monotonic() - started) * 1000)
            job.touch()
        finally:
            with self._lock:
                self._running = max(0, self._running - 1)

    def _execute(self, job: Job, keys: dict[str, str], started: float) -> None:
        identifier = job.identifier
        plan: list[tuple[SourceSpec, SourceResult | None]] = plan_for(identifier.kind, keys)
        pending: list[tuple[SourceSpec, int]] = []
        for spec, precomputed in plan:
            if precomputed is not None:
                job.results.append(precomputed)
                job._index[spec.id] = len(job.results) - 1
            else:
                job.results.append(SourceResult(
                    source_id=spec.id, source_name=spec.name, category=spec.category,
                    status=STATUS_PENDING, message="Queued - waiting for this source to run.",
                    sends=spec.sends,
                ))
                job._index[spec.id] = len(job.results) - 1
                pending.append((spec, len(job.results) - 1))
        job.touch()

        ctx = SourceContext(identifier=identifier, keys=keys, mode=job.mode, fetcher=self.fetcher)
        deadline = SETTINGS.limits.scan_total_timeout

        if pending:
            with futures.ThreadPoolExecutor(
                max_workers=min(len(pending), SETTINGS.limits.scan_worker_threads),
                thread_name_prefix=f"src-{job.id[:6]}",
            ) as pool:
                future_map = {pool.submit(execute, spec, ctx): (spec, index) for spec, index in pending}
                done, not_done = futures.wait(future_map, timeout=deadline)
                for future in done:
                    spec, index = future_map[future]
                    try:
                        job.results[index] = future.result()
                    except Exception as exc:  # pragma: no cover - execute() never raises
                        job.results[index] = SourceResult(
                            source_id=spec.id, source_name=spec.name, category=spec.category,
                            status=STATUS_ERROR, message=f"Source crashed: {type(exc).__name__}",
                            sends=spec.sends,
                        )
                    job.touch()
                for future in not_done:
                    spec, index = future_map[future]
                    future.cancel()
                    job.results[index] = SourceResult(
                        source_id=spec.id, source_name=spec.name, category=spec.category,
                        status=STATUS_UNAVAILABLE,
                        message=f"Source did not finish within the {deadline:.0f}s scan deadline.",
                        sends=spec.sends,
                    )
                    job.touch()

        job.finished_at = utcnow_iso()
        job.duration_ms = int((time.monotonic() - started) * 1000)
        job.privacy = build_privacy_disclosure(identifier, job.results)
        job.coverage = build_coverage(
            identifier, job.results,
            started_at=job.started_at or job.created_at, finished_at=job.finished_at,
            duration_ms=job.duration_ms,
        )
        if job.mode == "report":
            job.summary = build_summary(identifier, job.results, job.coverage)
        job.state = "complete"
        job.touch()

    # -- serialisation ------------------------------------------------------
    def snapshot(self, job: Job) -> dict[str, Any]:
        return {
            "scan_id": job.id,
            "state": job.state,
            "mode": job.mode,
            "identifier": job.identifier.as_dict(),
            "created_at": job.created_at,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "duration_ms": job.duration_ms,
            "version": job.version,
            "error": job.error,
            "sources": [r.as_dict() for r in job.results],
            "findings": [f.as_dict() for r in job.results for f in r.findings],
            "coverage": job.coverage,
            "privacy": job.privacy,
            "summary": job.summary,
            "source_catalogue": public_catalogue(),
            "app": {"version": APP_VERSION, "summary_engine": "deterministic-rules-v1"},
        }


def _iso_to_epoch(value: str) -> float:
    from datetime import datetime, timezone

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


STORE = JobStore()
