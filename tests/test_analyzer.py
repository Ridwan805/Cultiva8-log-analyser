import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app


class TestSecurityAnalyzer(unittest.TestCase):

    def setUp(self):
        app.init_db()

    def test_parse_json_with_think_tags(self):
        raw = '<think>This is internal reasoning.</think>{"findings": [{"type": "SQLi", "severity": "High", "actor": "1.2.3.4", "lines": [1], "reason": "test", "action": "block"}]}'
        data = app.parse_json(raw)
        self.assertIn('findings', data)
        self.assertEqual(len(data['findings']), 1)
        self.assertEqual(data['findings'][0]['type'], 'SQLi')

    def test_classify_family(self):
        self.assertEqual(app.classify_family('SQL injection attempts'), 'SQL injection')
        self.assertEqual(app.classify_family('Possible brute-force and account compromise'), 'Authentication attack')
        self.assertEqual(app.classify_family('Repeated authentication failures'), 'Authentication attack')
        self.assertEqual(app.classify_family('Sensitive endpoint reconnaissance'), 'Scanning')
        self.assertEqual(app.classify_family('Path traversal attempts'), 'Path traversal')
        self.assertEqual(app.classify_family('Unauthorized access attempts'), 'Unauthorized access')
        self.assertEqual(app.classify_family('Unusual API request burst'), 'Rate anomaly')
        self.assertEqual(app.classify_family('Log-based prompt injection attempt'), 'Prompt injection')

    def test_extract_line_contexts(self):
        chunk = (
            'L1: {"time":"2026-11-01T08:00:00Z","client_ip":"198.51.100.1","username":"alice"}\n'
            'L2: 2026-11-01 08:01:00 203.0.113.2 failed password for bob\n'
        )
        ctx = app.extract_line_contexts(chunk)
        self.assertEqual(ctx[1]['ip'], '198.51.100.1')
        self.assertEqual(ctx[1]['user'], 'alice')
        self.assertEqual(ctx[2]['ip'], '203.0.113.2')

    def test_normalize_ip_attribution(self):
        valid_lines = {1, 2}
        contexts = {
            1: {'ip': '203.0.113.44', 'user': 'admin', 'raw': '{"client_ip":"203.0.113.44","path":"/api/v1/auth/login","status":401,"auth_result":"invalid_password"}'},
            2: {'ip': '203.0.113.44', 'user': 'admin', 'raw': '{"client_ip":"203.0.113.44","path":"/api/v1/auth/login","status":401,"auth_result":"invalid_password"}'}
        }
        # Model hallucinated actor name "cultive8 workspace" instead of the IP
        raw_findings = [{
            'type': 'Authentication Failure',
            'severity': 'high',
            'actor': 'cultive8 workspace',
            'lines': [1, 2],
            'reason': 'Multiple 401s',
            'action': 'Investigate'
        }]
        normalized = app.normalize(raw_findings, valid_lines, contexts)
        self.assertEqual(len(normalized), 1)
        # Should attribute to true cited IP
        self.assertEqual(normalized[0]['actor'], '203.0.113.44')
        self.assertEqual(normalized[0]['severity'], 'High')
        self.assertEqual(normalized[0]['source'], 'Local AI')

    def test_rule_findings_plaintext(self):
        sample_path = ROOT / 'tests' / 'sample.txt'
        self.assertTrue(sample_path.exists())
        findings = app.rule_findings(str(sample_path))
        actors = {f['actor']: f for f in findings}
        # 192.0.2.14 had 5 failed logins followed by 1 accepted password
        self.assertIn('192.0.2.14', actors)
        self.assertEqual(actors['192.0.2.14']['severity'], 'Critical')
        # 198.51.100.25 had SQL injection probe
        self.assertIn('198.51.100.25', actors)
        # 203.0.113.5 had scanning endpoints (/.env, /.git/config, /wp-admin)
        self.assertIn('203.0.113.5', actors)

    def test_rule_findings_jsonl_assessment_log(self):
        log_path = ROOT / 'Cultive8_Workspace_Agrigen_Server.log'
        self.assertTrue(log_path.exists())
        findings = app.rule_findings(str(log_path))
        actors = {f['actor']: f for f in findings}

        # 203.0.113.44: Brute force & compromise
        self.assertIn('203.0.113.44', actors)
        compromise = [f for f in findings if f['actor'] == '203.0.113.44' and f['severity'] == 'Critical']
        self.assertTrue(len(compromise) > 0)
        self.assertIn(196, compromise[0]['lines'])  # Login success
        self.assertIn(201, compromise[0]['lines'])  # Export

        # 203.0.113.72: SQL injection
        self.assertIn('203.0.113.72', actors)
        sqli = [f for f in findings if f['actor'] == '203.0.113.72']
        self.assertTrue(any('sql' in f['type'].lower() for f in sqli))

        # 203.0.113.90: Reconnaissance & Path traversal
        self.assertIn('203.0.113.90', actors)

        # 203.0.113.155: API burst (429s)
        self.assertIn('203.0.113.155', actors)

        # 203.0.113.201: Prompt injection attempt
        self.assertIn('203.0.113.201', actors)
        prompt_inj = [f for f in findings if f['actor'] == '203.0.113.201']
        self.assertTrue(len(prompt_inj) > 0)
        self.assertIn(217, prompt_inj[0]['lines'])

        # Health monitor 192.0.2.10 should NOT be flagged as an attacker
        self.assertNotIn('192.0.2.10', actors)

    def test_consolidated_merging(self):
        job_id = 'test-merge-job'
        with app.conn() as db:
            # Simulate an AI finding for SQL injection from 203.0.113.72 on line 29
            ai_findings = [{
                'type': 'SQL Injection',
                'severity': 'Medium',
                'actor': '203.0.113.72',
                'lines': [29],
                'reason': 'AI detected SQL injection keywords in URL',
                'action': 'Block IP',
                'source': 'Local AI'
            }]
            db.execute('DELETE FROM findings WHERE job=?', (job_id,))
            db.execute('INSERT INTO findings(job,chunk,payload) VALUES(?,?,?)', (job_id, 1, json.dumps(ai_findings)))

        sample_path = ROOT / 'Cultive8_Workspace_Agrigen_Server.log'
        merged = app.consolidated(job_id, str(sample_path))
        sqli_merged = next((f for f in merged if f['actor'] == '203.0.113.72'), None)
        self.assertIsNotNone(sqli_merged)
        # Severity should be elevated to High (from rule)
        self.assertEqual(sqli_merged['severity'], 'High')
        # Source should reflect both AI and rule correlation
        self.assertEqual(sqli_merged['source'], 'Local AI + cross-file correlation')
        # Lines should include line 29
        self.assertIn(29, sqli_merged['lines'])

    def test_http_403_not_blindly_flagged(self):
        # A routine 403 on a non-admin endpoint without access_denied rule should not be treated as an attack
        with tempfile.NamedTemporaryFile('w', suffix='.log', delete=False, encoding='utf-8') as f:
            f.write('{"time":"2026-11-01T08:00:00Z","client_ip":"198.51.100.55","path":"/profile","status":403}\n')
            temp_path = f.name
        try:
            findings = app.rule_findings(temp_path)
            self.assertEqual(len(findings), 0, "Routine non-admin 403 was incorrectly flagged as an attack")
        finally:
            os.unlink(temp_path)

    def test_evidence_validation_rejects_hallucinations(self):
        valid_lines = {1, 2, 3}
        contexts = {
            1: {'ip': '198.51.100.1', 'user': None, 'raw': '{"path":"/","status":200}'},
            2: {'ip': '198.51.100.2', 'user': None, 'raw': '{"path":"/api/v1/harvest?id=12","status":200}'},
            3: {'ip': '198.51.100.3', 'user': None, 'raw': '{"path":"/dashboard","status":503}'}
        }
        # Model hallucinating attacks on benign lines
        hallucinations = [
            {'type': 'Path Traversal', 'severity': 'High', 'actor': '198.51.100.1', 'lines': [1]},
            {'type': 'SQL Injection', 'severity': 'High', 'actor': '198.51.100.2', 'lines': [2]},
            {'type': 'Authentication Failure', 'severity': 'High', 'actor': '198.51.100.3', 'lines': [3]}
        ]
        result = app.normalize(hallucinations, valid_lines, contexts)
        self.assertEqual(len(result), 0, "AI hallucinations on benign lines should be rejected by evidence verification")

    def test_chunking_token_budget(self):
        log_path = ROOT / 'Cultive8_Workspace_Agrigen_Server.log'
        chunk_count = 0
        for ch in app.chunks(str(log_path)):
            chunk_count += 1
            prompt = 'Return concise JSON findings only. Logs (line-numbered):\n' + ch
            total = app.count_tokens(app.SYSTEM) + app.count_tokens(prompt) + app.OUTPUT_TOKENS + 80
            self.assertLessEqual(total, app.BUDGET, f"Chunk {chunk_count} exceeded token budget: {total} > {app.BUDGET}")
        self.assertGreater(chunk_count, 0)

    def test_parse_json_truncated_repair(self):
        # Truncated JSON where Ollama cut off during the second finding
        raw_truncated = (
            '{\n'
            '  "findings": [\n'
            '    {\n'
            '      "type": "Authentication Failure",\n'
            '      "severity": "High",\n'
            '      "actor": "client_ip:198.51.100.97",\n'
            '      "lines": [192],\n'
            '      "reason": "Test reason",\n'
            '      "action": "Block IP"\n'
            '    },\n'
            '    {\n'
            '      "type": "Authentication Failure",\n'
            '      "severity": "High",\n'
            '      "actor": "client_ip:203.0.113.44",\n'
            '      "lines": [195, 198],\n'
            '      "reason": "User agent \'python-requests'
        )
        parsed = app.parse_json(raw_truncated)
        self.assertIn('findings', parsed)
        self.assertEqual(len(parsed['findings']), 1)
        self.assertEqual(parsed['findings'][0]['actor'], 'client_ip:198.51.100.97')

    def test_known_hallucinations_rejected(self):
        log_path = ROOT / 'Cultive8_Workspace_Agrigen_Server.log'
        self.assertTrue(log_path.exists())
        lines_to_check = [40, 82, 93, 99, 124, 135, 174, 199, 247, 252, 258]
        contexts = {}
        with open(log_path, 'r', encoding='utf-8') as f:
            for n, line in enumerate(f, 1):
                if n in lines_to_check:
                    try:
                        d = json.loads(line)
                        contexts[n] = {'ip': d.get('client_ip'), 'user': d.get('username'), 'raw': line.strip(), 'dict': d}
                    except Exception:
                        contexts[n] = {'ip': None, 'user': None, 'raw': line.strip(), 'dict': None}

        # Model hallucinations claiming attacks on benign lines
        hallucinations = [
            {'type': 'SQL Injection', 'severity': 'High', 'actor': '198.51.100.102', 'lines': [40]},
            {'type': 'Path Traversal', 'severity': 'High', 'actor': '198.51.100.80', 'lines': [82]},
            {'type': 'Authentication Failure', 'severity': 'High', 'actor': '198.51.100.110', 'lines': [93]},
            {'type': 'SQL Injection', 'severity': 'High', 'actor': '203.0.113.90', 'lines': [99]}, # Line 99 is traversal, not SQLi
            {'type': 'SQL Injection', 'severity': 'High', 'actor': '198.51.100.96', 'lines': [124]},
            {'type': 'Authentication Failure', 'severity': 'High', 'actor': '198.51.100.91', 'lines': [135]},
            {'type': 'Unauthorized Access', 'severity': 'High', 'actor': '198.51.100.95', 'lines': [174]},
            {'type': 'Unauthorized Access', 'severity': 'High', 'actor': '198.51.100.95', 'lines': [199]},
            {'type': 'Unauthorized Access', 'severity': 'High', 'actor': '198.51.100.104', 'lines': [247]},
            {'type': 'SQL Injection', 'severity': 'High', 'actor': '198.51.100.86', 'lines': [252]},
            {'type': 'Unauthorized Access', 'severity': 'High', 'actor': 'cultive8', 'lines': [258]}, # Scheduled backup
        ]
        result = app.normalize(hallucinations, set(lines_to_check), contexts)
        self.assertEqual(len(result), 0, f"Expected 0 findings but got {len(result)}: {result}")

    def test_rate_anomaly_deduplication(self):
        job_id = 'test-rate-dedup'
        # Multiple chunk findings for rate limiting on the same actor
        chunk_findings_1 = [{
            'type': 'Rate limit exceeded (HTTP 429)',
            'severity': 'Medium',
            'actor': '203.0.113.155',
            'lines': [162, 163],
            'reason': 'Too many requests',
            'action': 'Throttle IP',
            'source': 'Local AI'
        }]
        chunk_findings_2 = [{
            'type': 'Unusual API request burst',
            'severity': 'Medium',
            'actor': '203.0.113.155',
            'lines': [164, 165],
            'reason': 'High request rate',
            'action': 'Throttle IP',
            'source': 'Local AI'
        }]
        with app.conn() as db:
            db.execute('DELETE FROM findings WHERE job=?', (job_id,))
            db.execute('INSERT INTO findings(job,chunk,payload) VALUES(?,?,?)', (job_id, 20, json.dumps(chunk_findings_1)))
            db.execute('INSERT INTO findings(job,chunk,payload) VALUES(?,?,?)', (job_id, 21, json.dumps(chunk_findings_2)))

        sample_path = ROOT / 'Cultive8_Workspace_Agrigen_Server.log'
        merged = app.consolidated(job_id, str(sample_path))
        rate_findings = [f for f in merged if f['actor'] == '203.0.113.155']
        # Must be merged into exactly one rate-anomaly finding
        self.assertEqual(len(rate_findings), 1, "Duplicate rate limit findings were not consolidated into one incident")
        self.assertIn(162, rate_findings[0]['lines'])
        self.assertIn(165, rate_findings[0]['lines'])


if __name__ == '__main__':
    unittest.main()

