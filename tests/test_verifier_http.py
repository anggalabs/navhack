from __future__ import annotations

import unittest

from navhack import httpio, util, verifier
from navhack.models import Budget, Finding
from navhack.policy import Policy
from navhack.scope import Scope

from .labserver import Lab


def policy_for(hosts=("127.0.0.1",), **kwargs):
    budget = dict(max_requests=200, max_noise=100, rate_per_second=1000.0, dry_run=False)
    budget.update(kwargs)
    return Policy(Scope.parse(list(hosts)), Budget(**budget))


class OOBTests(unittest.TestCase):
    def test_capture_and_wait(self) -> None:
        with verifier.OOB() as oob:
            url = oob.token_url("tok123")
            httpio.get(url, policy=policy_for())
            hit = oob.wait("tok123", timeout=5)
            self.assertIsNotNone(hit)
            self.assertEqual(hit["token"], "tok123")
            self.assertEqual(oob.describe()["hits"], 1)

    def test_wait_timeout(self) -> None:
        with verifier.OOB() as oob:
            self.assertIsNone(oob.wait("nope", timeout=0.3))

    def test_public_url_override(self) -> None:
        oob = verifier.OOB(public="10.1.2.3:9000")
        self.assertEqual(oob.base_url(), "http://10.1.2.3:9000")
        self.assertTrue(oob.token_url("t").endswith("/t"))

    def test_loopback_hint(self) -> None:
        oob = verifier.OOB()
        self.assertIn("loopback", verifier.oob_hint(oob, "10.0.0.5").lower())


class ProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lab = Lab().start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.lab.stop()

    def test_exposure_marker(self) -> None:
        finding = Finding(title="x", primitive="exposure", target=self.lab.base + "/.env")
        proof = verifier.verify_finding(finding, policy=policy_for())
        self.assertTrue(proof.ok)
        self.assertTrue(proof.digest)

    def test_file_read_marker(self) -> None:
        finding = Finding(title="x", primitive="lfi", target=self.lab.base + "/file")
        proof = verifier.verify_finding(finding, policy=policy_for())
        self.assertTrue(proof.ok)

    def test_xss_reflection(self) -> None:
        finding = Finding(title="x", primitive="xss", target=self.lab.base + "/search?q=hi")
        proof = verifier.verify_finding(finding, policy=policy_for())
        self.assertTrue(proof.ok)

    def test_negative_for_missing_signature(self) -> None:
        finding = Finding(title="x", primitive="file_read", target=self.lab.base + "/nothing")
        proof = verifier.verify_finding(finding, policy=policy_for())
        self.assertFalse(proof.ok)

    def test_ssrf_uses_oob(self) -> None:
        with verifier.OOB() as oob:
            finding = Finding(title="x", primitive="ssrf", target=self.lab.base + "/search?q=hi")
            proof = verifier.verify_finding(finding, policy=policy_for(), oob=oob)
            self.assertTrue(proof.ok)

    def test_out_of_scope_target(self) -> None:
        finding = Finding(title="x", primitive="exposure", target="http://127.0.0.1:%d/.env" % self.lab.port)
        proof = verifier.verify_finding(finding, policy=policy_for(hosts=("example.com",)))
        self.assertFalse(proof.ok)


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lab = Lab().start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.lab.stop()

    def test_get(self) -> None:
        response = httpio.get(self.lab.base + "/", policy=policy_for())
        self.assertEqual(response.status, 200)
        self.assertIn("lab", response.text)

    def test_redirect_chain(self) -> None:
        response = httpio.get(self.lab.base + "/redirect?next=/.env", policy=policy_for())
        self.assertEqual(response.status, 200)
        self.assertEqual(response.redirects[0], self.lab.base + "/.env")

    def test_body_cap(self) -> None:
        response = httpio.get(self.lab.base + "/big", policy=policy_for(), max_bytes=100)
        self.assertEqual(len(response.body), 100)
        self.assertTrue(response.truncated)

    def test_out_of_scope_error(self) -> None:
        response = httpio.get("http://127.0.0.1:%d/" % self.lab.port, policy=policy_for(hosts=("example.com",)))
        self.assertIn("out of scope", response.error)

    def test_probe_tcp(self) -> None:
        ok, _elapsed, _error = httpio.probe_tcp("127.0.0.1", self.lab.port, policy=policy_for())
        self.assertTrue(ok)

    def test_probe_tcp_closed_port(self) -> None:
        ok, _elapsed, _error = httpio.probe_tcp("127.0.0.1", 1, policy=policy_for(), timeout=0.3)
        self.assertFalse(ok)

    def test_5xx_aborts_policy(self) -> None:
        policy = policy_for(abort_5xx=2)
        httpio.get(self.lab.base + "/flaky", policy=policy)
        self.assertFalse(policy.aborted)
        httpio.get(self.lab.base + "/flaky", policy=policy)
        self.assertTrue(policy.aborted)
        response = httpio.get(self.lab.base + "/", policy=policy)
        self.assertIn("aborted", response.error)

    def test_mask_headers(self) -> None:
        masked = util.mask_headers([("Set-Cookie", "sid=abcdef123456"), ("Server", "x" * 400)])
        self.assertIn("***", masked["Set-Cookie"])
        self.assertLessEqual(len(masked["Server"]), 300)


if __name__ == "__main__":
    unittest.main()
