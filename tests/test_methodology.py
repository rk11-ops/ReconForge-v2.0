import unittest

from reconforge.methodology import OWASP_TOP10_2025, CWE_TOP25_2025, build_methodology_coverage, methodology_annotations, apply_methodology_annotations


class MethodologyTests(unittest.TestCase):
    def test_pack_sizes(self):
        self.assertEqual(len(OWASP_TOP10_2025), 10)
        self.assertEqual(len(CWE_TOP25_2025), 25)
        self.assertEqual([x["rank"] for x in CWE_TOP25_2025], list(range(1, 26)))

    def test_known_cwe_mapping(self):
        finding = {"rule_id": "RF-WEB-018", "cwe": "CWE-79", "name": "reflected input"}
        a = methodology_annotations(finding)
        self.assertEqual(a["owasp_2025_id"], "A05:2025")
        self.assertEqual(a["cwe_top25_2025_rank"], 1)

    def test_build_coverage_and_statuses(self):
        findings = [{"rule_id":"RF-WEB-024","cwe":"CWE-89","evidence_state":"NEEDS_VALIDATION","name":"SQL injection review candidate"}]
        coverage = build_methodology_coverage(findings=findings, pages=[{"url":"https://example.test/","forms":[]}], selected="all")
        self.assertEqual(len(coverage["owasp_top10_2025"]), 10)
        self.assertEqual(len(coverage["cwe_top25_2025"]), 25)
        sql = next(x for x in coverage["cwe_top25_2025"] if x["id"] == "CWE-89")
        self.assertEqual(sql["status"], "candidate")
        mem = next(x for x in coverage["cwe_top25_2025"] if x["id"] == "CWE-787")
        self.assertEqual(mem["status"], "source-review")

    def test_apply_promotes_current_owasp_label(self):
        finding = {"rule_id":"RF-WEB-017","cwe":"CWE-352","owasp_category":"old label","name":"csrf"}
        out = apply_methodology_annotations([finding])[0]
        self.assertEqual(out["owasp_category"], "A01:2025 Broken Access Control")


if __name__ == "__main__":
    unittest.main()
