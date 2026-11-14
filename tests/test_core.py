"""Core tests for the SOC Dashboard.

Covers the pieces where a regression would be a security regression:
log parsing, redirect target validation, CSRF enforcement and the
authentication flow.

Run with:  python -m unittest discover -s tests -v
"""

import os
import sys
import tempfile
import unittest

# Configure the application before importing it. Without these the module would
# create a .secret_key file and reuse the bundled database.
_TMP = tempfile.mkdtemp(prefix="soc-test-")
os.environ["SOC_DATABASE"] = os.path.join(_TMP, "test.db")
os.environ["SOC_SECRET_KEY"] = "test-secret-key-not-for-production-use"
os.environ["SOC_ADMIN_PASSWORD"] = "TestAdmin!2026"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dashboard  # noqa: E402


class ParseLogLineTests(unittest.TestCase):
    def test_blank_line_is_skipped(self):
        self.assertIsNone(dashboard.parse_log_line("   "))

    def test_ssh_failure_is_classified(self):
        entry = dashboard.parse_log_line(
            "2026-09-01T10:00:00 Failed password for invalid user admin "
            "from 192.168.1.50 port 51422 ssh2"
        )
        self.assertEqual(entry["event_type"], "Failed SSH Login")
        self.assertEqual(entry["severity"], "MEDIUM")
        self.assertEqual(entry["source_ip"], "192.168.1.50")
        self.assertEqual(entry["destination_port"], "51422")
        self.assertEqual(entry["timestamp"], "2026-09-01T10:00:00")

    def test_port_scan_is_high(self):
        entry = dashboard.parse_log_line("Port scan detected from 10.0.0.9")
        self.assertEqual(entry["event_type"], "Port Scan Detected")
        self.assertEqual(entry["severity"], "HIGH")
        self.assertEqual(entry["source_ip"], "10.0.0.9")

    def test_malware_is_critical(self):
        entry = dashboard.parse_log_line("Malware signature matched on host 172.16.1.13")
        self.assertEqual(entry["event_type"], "Malware Detection")
        self.assertEqual(entry["severity"], "CRITICAL")

    def test_csv_row_is_normalized(self):
        entry = dashboard.parse_log_line(
            "2026-09-01T12:00:00,192.168.1.10,10.0.0.5,Port Scan Detected,HIGH,"
            "nmap sweep"
        )
        self.assertEqual(entry["timestamp"], "2026-09-01T12:00:00")
        self.assertEqual(entry["source_ip"], "192.168.1.10")
        self.assertEqual(entry["destination_ip"], "10.0.0.5")
        self.assertEqual(entry["event_type"], "Port Scan Detected")
        self.assertEqual(entry["severity"], "HIGH")
        self.assertEqual(entry["raw_message"], "nmap sweep")

    def test_unknown_text_never_raises(self):
        entry = dashboard.parse_log_line("hello, this is not a log line at all")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["severity"], "LOW")
        self.assertIn("raw_message", entry)

    def test_non_string_input_is_handled(self):
        entry = dashboard.parse_log_line(None)
        self.assertIsNone(entry)


class SafeNextUrlTests(unittest.TestCase):
    """?next= must never produce a redirect off-site."""

    def _resolve(self, query):
        with dashboard.app.test_request_context("/login" + query):
            return dashboard._safe_next_url()

    def test_relative_path_is_allowed(self):
        self.assertEqual(self._resolve("?next=/logs"), "/logs")

    def test_absolute_url_is_rejected(self):
        self.assertEqual(self._resolve("?next=https://evil.example/"), "/dashboard")

    def test_protocol_relative_url_is_rejected(self):
        self.assertEqual(self._resolve("?next=//evil.example/"), "/dashboard")

    def test_scheme_relative_without_slashes_is_rejected(self):
        self.assertEqual(self._resolve("?next=javascript:alert(1)"), "/dashboard")

    def test_missing_next_falls_back(self):
        self.assertEqual(self._resolve(""), "/dashboard")


class AuthFlowTests(unittest.TestCase):
    def setUp(self):
        dashboard.app.config.update(TESTING=True)
        dashboard.init_db()
        dashboard._login_failures.clear()
        self.client = dashboard.app.test_client()

    def _csrf_from_login_page(self):
        page = self.client.get("/login")
        self.assertEqual(page.status_code, 200)
        body = page.get_data(as_text=True)
        marker = 'name="csrf_token" value="'
        start = body.index(marker) + len(marker)
        return body[start:body.index('"', start)]

    def test_post_without_csrf_is_rejected(self):
        response = self.client.post(
            "/login", data={"username": "admin", "password": "TestAdmin!2026"}
        )
        self.assertEqual(response.status_code, 400)

    def test_wrong_password_is_rejected(self):
        token = self._csrf_from_login_page()
        response = self.client.post(
            "/login",
            data={"username": "admin", "password": "wrong", "csrf_token": token},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid username or password", response.get_data(as_text=True))

    def test_correct_password_redirects_to_dashboard(self):
        token = self._csrf_from_login_page()
        response = self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": "TestAdmin!2026",
                "csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/dashboard"))

    def test_open_redirect_is_neutralised(self):
        token = self._csrf_from_login_page()
        response = self.client.post(
            "/login?next=https://evil.example/",
            data={
                "username": "admin",
                "password": "TestAdmin!2026",
                "csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("evil.example", response.headers["Location"])
        self.assertTrue(response.headers["Location"].endswith("/dashboard"))

    def test_protected_route_requires_login(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_login_page_does_not_advertise_default_credentials(self):
        body = self.client.get("/login").get_data(as_text=True)
        self.assertNotIn("admin123", body)
        self.assertNotIn("Default demo credentials", body)

    def test_schema_is_recreated_when_missing(self):
        """A database that loses its tables must not turn into a 500 loop."""
        import sqlite3

        con = sqlite3.connect(os.environ["SOC_DATABASE"])
        con.execute("DROP TABLE IF EXISTS logs")
        con.commit()
        con.close()
        dashboard._schema_ready = False

        token = self._csrf_from_login_page()
        self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": "TestAdmin!2026",
                "csrf_token": token,
            },
        )
        response = self.client.get("/api/dashboard")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
