import csv
import logging
from pathlib import Path
import unittest

from demo import probes_per_window
from pressure_model import CAPACITY, REQUEST_PROFILES, SCENARIOS, TICKS, QueueModel
from syn_defense_agent import DefenseAgent, Reading

CASES = {scenario.key: scenario for scenario in SCENARIOS}


def windows(key):
    model = QueueModel(CASES[key])
    agent = DefenseAgent(20, 2, model.enable_cookies)
    samples = []
    for tick in range(1, TICKS + 1):
        row = model.step(tick)
        samples.append((row, agent.sample(Reading(str(tick), row.syn_recv_count, row.syn_ack_ratio))))
    return samples


class TestPipeline(unittest.TestCase):
    def test_both_outcomes_activate_at_same_time(self):
        success = windows("auto-success")
        failure = windows("auto-failure")
        for run in (success, failure):
            self.assertEqual([decision.event for _, decision in run].count("suspected SYN flood"), 1)
            self.assertEqual(run[2][1].defense_status, "active")
            self.assertEqual(run[2][0].decisions.count("served"), 0)
            self.assertEqual([row.syn_recv_count for row, _ in run[3:]], [CAPACITY] * 3)
        self.assertEqual(sum(row.decisions.count("served") for row, _ in success[3:]), 12)
        self.assertEqual(sum(row.decisions.count("served") for row, _ in failure[3:]), 3)

    def test_per_source_filter_depends_on_grouping(self):
        fixed = QueueModel(CASES["filter-single"]).step(2)
        changing = QueueModel(CASES["filter-distributed"]).step(2)
        self.assertEqual((fixed.per_source_drops, fixed.syn_recv_count), (36, 2))
        self.assertEqual((changing.per_source_drops, changing.syn_recv_count), (0, CAPACITY))
        self.assertEqual(fixed.pressure_arrivals, changing.pressure_arrivals)

    def test_workload_profiles_keep_the_pressure_fixture_fixed(self):
        normal, recovery, limited = (CASES[key] for key in ("baseline", "auto-success", "auto-failure"))
        for total in REQUEST_PROFILES:
            with self.subTest(requests=total):
                schedule = probes_per_window(total)
                self.assertEqual(sum(schedule), total)
                self.assertLessEqual(max(schedule) - min(schedule), 1)
                baseline, success, failure = map(QueueModel, (normal, recovery, limited))
                successful_after, limited_after = 0, 0
                for tick, count in enumerate(schedule, 1):
                    if tick == 4:
                        success.enable_cookies()
                        failure.enable_cookies()
                    self.assertEqual(baseline.step(tick, count).decisions.count("served"), count)
                    recovered, bottleneck = success.step(tick, count), failure.step(tick, count)
                    self.assertEqual(recovered.pressure_arrivals, 38 if tick >= 2 else 0)
                    self.assertEqual(recovered.pressure_arrivals, bottleneck.pressure_arrivals)
                    if tick >= 4:
                        successful_after += recovered.decisions.count("served")
                        limited_after += bottleneck.decisions.count("served")
                self.assertEqual(successful_after, sum(schedule[3:]))
                self.assertEqual(limited_after, sum(schedule[1:]) // 4 - sum(schedule[1:3]) // 4)

    def test_recovery_resets_consecutive_count_and_activation_is_idempotent(self):
        calls = []
        agent = DefenseAgent(20, 2, lambda: calls.append("enabled"))
        for count in (20, 19, 20):
            self.assertEqual(agent.sample(Reading("now", count, None)).defense_status, "watching")
        for count in (20, 32, 0):
            self.assertEqual(agent.sample(Reading("now", count, None)).defense_status, "active")
        self.assertEqual(calls, ["enabled"])

    def test_backend_failure_can_retry(self):
        calls = iter((False, True))

        def activate():
            if not next(calls):
                raise RuntimeError("first activation failed")

        agent = DefenseAgent(20, 1, activate)
        with self.assertLogs("syn_defense_agent", level=logging.ERROR):
            self.assertEqual(agent.sample(Reading("1", 20, None)).defense_status, "error")
        self.assertEqual(agent.sample(Reading("2", 20, None)).defense_status, "active")

    def test_recorded_demo_matches_the_comparison(self):
        path = Path(__file__).resolve().parents[1] / "evidence" / "http.csv"
        with path.open(newline="") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 7 * 24)
        for row in rows:
            expected = "200" if row["modeled_verdict"] == "served" else "503"
            self.assertEqual(row["status"], expected)
        for key, expected in (("auto-success", 12), ("auto-failure", 3)):
            active = [row for row in rows if row["scenario"] == key and row["defense_active"] == "True"]
            self.assertEqual(len(active), 12)
            self.assertEqual(sum(row["status"] == "200" for row in active), expected)


if __name__ == "__main__":
    unittest.main()
