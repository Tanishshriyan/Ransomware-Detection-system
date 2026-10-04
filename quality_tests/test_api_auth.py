import unittest

from fastapi import HTTPException

from backend.main import app, config, require_api_key


class ApiAuthTests(unittest.TestCase):
    def setUp(self):
        self.original_security = dict(config.config_data.get("security", {}))
        config.config_data["security"] = {
            **self.original_security,
            "enable_authentication": True,
            "api_key": "test-api-key",
        }

    def tearDown(self):
        if self.original_security:
            config.config_data["security"] = self.original_security
        else:
            config.config_data.pop("security", None)

    def test_dependency_rejects_missing_or_invalid_keys(self):
        for supplied in (None, "wrong-key"):
            with self.subTest(supplied=supplied):
                with self.assertRaises(HTTPException) as context:
                    require_api_key(supplied)
                self.assertEqual(context.exception.status_code, 401)

    def test_dependency_accepts_configured_key(self):
        self.assertIsNone(require_api_key("test-api-key"))

    def test_every_api_route_uses_the_auth_dependency(self):
        api_routes = [
            route
            for route in app.routes
            if getattr(route, "path", "").startswith("/api/")
            and getattr(route, "path", "") not in {"/api/docs", "/api/redoc"}
        ]
        self.assertTrue(api_routes)
        unprotected = []
        for route in api_routes:
            dependant = getattr(route, "dependant", None)
            dependency_calls = {
                dependency.call
                for dependency in getattr(dependant, "dependencies", [])
            }
            if require_api_key not in dependency_calls:
                unprotected.append(route.path)

        self.assertEqual(unprotected, [])


if __name__ == "__main__":
    unittest.main()
