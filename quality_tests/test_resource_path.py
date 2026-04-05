import unittest
from pathlib import Path
from unittest import mock

from utils import resource_path


class ResourcePathTests(unittest.TestCase):
    def test_resolve_runtime_path_preserves_absolute_paths(self):
        absolute_path = str((Path.cwd() / "config.yaml").resolve())
        self.assertEqual(resource_path.resolve_runtime_path(absolute_path), absolute_path)

    def test_runtime_or_resource_path_prefers_runtime_copy(self):
        with mock.patch("utils.resource_path.runtime_path", return_value="D:/app/config.yaml"):
            with mock.patch("utils.resource_path.resource_path", return_value="D:/bundle/config.yaml"):
                with mock.patch("utils.resource_path.Path.exists", return_value=True):
                    resolved = resource_path.runtime_or_resource_path("config.yaml")

        self.assertEqual(Path(resolved), Path("D:/app/config.yaml"))

    def test_runtime_or_resource_path_falls_back_to_bundle(self):
        with mock.patch("utils.resource_path.runtime_path", return_value="D:/app/config.yaml"):
            with mock.patch("utils.resource_path.resource_path", return_value="D:/bundle/config.yaml"):
                with mock.patch("utils.resource_path.Path.exists", return_value=False):
                    resolved = resource_path.runtime_or_resource_path("config.yaml")

        self.assertEqual(Path(resolved), Path("D:/bundle/config.yaml"))
