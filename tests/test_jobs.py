"""Tests for scan-job orchestration: state machine, bounded lifetime, capacity."""

from __future__ import annotations

import dataclasses
import time
import unittest

from stubs import *  # noqa: F401,F403
from stubs import UpstreamTimeout, make_fetcher

from app.config import SETTINGS
from app.identifiers import detect
from app.jobs import CapacityError, JobStore
from app.sources.base import (
    STATUS_NO_MATCH,
    STATUS_NOT_CHECKED,
    STATUS_OK,
    STATUS_PENDING,
    STATUS_UNAVAILABLE,
)


def wait_for(job, timeout=25.0):
    deadline = time.monotonic() + timeout
    while job.state not in ("complete", "failed") and time.monotonic() < deadline:
        time.sleep(0.02)
    return job


class JobLifecycleTests(unittest.TestCase):
    def setUp(self):
        # Phone numbers are analysed locally, so this scan needs no network at all.
        fetcher, self.transport = make_fetcher([])
        self.store = JobStore(fetcher=fetcher)

    def test_local_only_scan_completes(self):
        job = self.store.create(detect("+442071234567"), "osint")
        wait_for(job)
        self.assertEqual(job.state, "complete")
        self.assertIsNone(job.error)
        self.assertEqual(len(job.results), 1)
        self.assertEqual(job.results[0].source_id, "phone_local")
        self.assertEqual(job.results[0].status, STATUS_OK)
        self.assertEqual(self.transport.calls, [])  # nothing left the process
        self.assertGreater(job.version, 0)
        self.assertIsNotNone(job.coverage)
        self.assertIsNone(job.summary)  # osint mode does not build a report

    def test_report_mode_builds_a_summary(self):
        job = self.store.create(detect("+442071234567"), "report")
        wait_for(job)
        self.assertEqual(job.state, "complete")
        self.assertIsNotNone(job.summary)
        self.assertEqual(job.summary["engine"], "deterministic-rules-v1")
        self.assertTrue(job.summary["sections"])

    def test_snapshot_shape_is_what_the_ui_polls(self):
        job = self.store.create(detect("+442071234567"), "report")
        wait_for(job)
        snap = self.store.snapshot(job)
        for key in ("scan_id", "state", "mode", "identifier", "version", "sources", "findings",
                    "coverage", "privacy", "summary", "source_catalogue", "app"):
            self.assertIn(key, snap)
        self.assertEqual(snap["scan_id"], job.id)
        self.assertEqual(snap["state"], "complete")
        self.assertEqual(snap["app"]["summary_engine"], "deterministic-rules-v1")
        self.assertTrue(snap["source_catalogue"])
        self.assertTrue(snap["privacy"])
        # The snapshot is what gets serialised to the client: no key material, no full history.
        self.assertEqual(len(snap["sources"]), 1)

    def test_no_result_is_left_in_pending_state(self):
        fetcher, _ = make_fetcher([(r".*", UpstreamTimeout("timed out"))], default=UpstreamTimeout("timed out"))
        store = JobStore(fetcher=fetcher)
        job = store.create(detect("example.com"), "report")
        wait_for(job, timeout=60)
        self.assertEqual(job.state, "complete")
        statuses = {r.status for r in job.results}
        self.assertNotIn(STATUS_PENDING, statuses)
        self.assertTrue(statuses <= {STATUS_UNAVAILABLE, STATUS_NO_MATCH, STATUS_NOT_CHECKED, STATUS_OK})

    def test_all_sources_failing_still_produces_an_honest_report(self):
        fetcher, _ = make_fetcher([(r".*", UpstreamTimeout("timed out"))], default=UpstreamTimeout("timed out"))
        store = JobStore(fetcher=fetcher)
        job = store.create(detect("example.com"), "report")
        wait_for(job, timeout=60)
        self.assertEqual(job.state, "complete")
        self.assertEqual(job.coverage["succeeded"], 0)
        self.assertEqual(job.summary["data_confidence"], "insufficient-data")
        self.assertIn("Insufficient data", job.summary["headline"])

    def test_unknown_job_id(self):
        self.assertIsNone(self.store.get("deadbeefdeadbeef"))

    def test_finished_jobs_are_pruned_after_the_ttl(self):
        job = self.store.create(detect("+442071234567"), "osint")
        wait_for(job)
        self.assertIsNotNone(self.store.get(job.id))
        job.finished_at = "2020-01-01T00:00:00Z"  # far older than job_ttl_seconds
        self.store.prune()
        self.assertIsNone(self.store.get(job.id))

    def test_stats_report_bounded_state(self):
        job = self.store.create(detect("+442071234567"), "osint")
        wait_for(job)
        stats = self.store.stats()
        self.assertEqual(stats["jobs"], 1)
        self.assertEqual(stats["running"], 0)


class CapacityTests(unittest.TestCase):
    def test_capacity_error_when_the_queue_is_full(self):
        fetcher, _ = make_fetcher([])
        store = JobStore(fetcher=fetcher)
        store._running = SETTINGS.limits.max_queued_scans + SETTINGS.limits.max_concurrent_scans
        with self.assertRaises(CapacityError):
            store.create(detect("+442071234567"), "osint")
        store._running = 0

    def test_job_count_is_bounded(self):
        fetcher, _ = make_fetcher([])
        store = JobStore(fetcher=fetcher)
        original = SETTINGS.limits
        SETTINGS.limits = dataclasses.replace(original, max_jobs=3, max_queued_scans=50)
        try:
            jobs = [store.create(detect("+442071234567"), "osint") for _ in range(6)]
            for job in jobs[-3:]:
                wait_for(job)
            self.assertLessEqual(len(store._jobs), 3)
            self.assertIsNone(store.get(jobs[0].id))  # oldest evicted
        finally:
            SETTINGS.limits = original


class ConcurrencyTests(unittest.TestCase):
    def test_scans_run_in_parallel_and_all_finish(self):
        fetcher, _ = make_fetcher([])
        store = JobStore(fetcher=fetcher)
        jobs = [store.create(detect("+442071234567"), "osint") for _ in range(4)]
        for job in jobs:
            wait_for(job)
        self.assertTrue(all(job.state == "complete" for job in jobs))
        self.assertEqual(len({job.id for job in jobs}), 4)
        self.assertEqual(store.stats()["running"], 0)


if __name__ == "__main__":
    unittest.main()
