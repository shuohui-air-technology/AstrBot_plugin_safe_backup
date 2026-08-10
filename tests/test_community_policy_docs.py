import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CommunityPolicyDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zh = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.en = (ROOT / "README_EN.md").read_text(encoding="utf-8")
        cls.security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        cls.changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        cls.schema = json.loads((ROOT / "_conf_schema.json").read_text(encoding="utf-8"))

    def test_automatic_retention_is_fail_closed_and_bounded(self):
        retention = self.schema["retention_count"]
        for token in ("可信", "最大保留", "默认 5"):
            self.assertIn(token, retention["description"])
        for token in ("最多保留", "默认 5", "外来", "损坏", "永不自动删除"):
            self.assertIn(token, retention["hint"])

        for token in ("自动保留默认上限为 5 份", "retention_count", "权威状态日志", "任何一步不确定"):
            self.assertIn(token, self.zh)
        for token in ("Automatic retention defaults to five archives", "retention_count", "authoritative journal", "Any uncertainty"):
            self.assertIn(token, self.en)

        self.assertNotIn("自动 retention 已禁用", self.zh)
        self.assertNotIn("Automatic retention is disabled", self.en)

    def test_staging_cleanup_and_quarantine_contract_is_explicit(self):
        for token in ("当前 run", "完整身份登记", "敏感 quarantine", "保留并报告"):
            self.assertIn(token, self.zh)
        for token in ("current run", "complete identity registration", "sensitive quarantine", "preserved and reported"):
            self.assertIn(token, self.en)

    def test_archive_verification_claim_is_precisely_scoped(self):
        for content in (self.zh, self.en, self.security):
            lowered = content.casefold()
            self.assertIn("crc", lowered)
            self.assertIn("sha256", lowered)
            self.assertIn("sqlite", lowered)
            self.assertNotIn("complete internal and extracted-tree verification", lowered)
            self.assertNotIn("完整物化全树", content)

    def test_task_lifecycle_and_threat_boundary_are_explicit(self):
        for token in ("update/remove", "用户显式", "同一 Windows 账户", "精确 TOCTOU", "祖先 junction", "自然并发"):
            self.assertIn(token, self.zh)
        for token in ("update/remove", "explicit user action", "same Windows account", "precise TOCTOU", "ancestor junction", "benign concurrency"):
            self.assertIn(token, self.en)

        for token in ("precise TOCTOU", "ancestor junction", "benign races fail closed"):
            self.assertIn(token, self.security)

    def test_changelog_matches_the_community_policy(self):
        for token in ("fail-closed automatic retention", "sensitive quarantine", "precise same-account TOCTOU"):
            self.assertIn(token.casefold(), self.changelog.casefold())
        self.assertIn("explicitly runs setup", self.changelog)
        self.assertIn("daily schedule automatically attempts", self.changelog)
        self.assertNotIn("No automatic backup", self.changelog)

    def test_release_repository_policy_excludes_local_implementation_material(self):
        ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
        prompt = (ROOT / "PUBLISHING_AGENT_PROMPT.md").read_text(encoding="utf-8")
        package_allowlist = (ROOT / "scripts" / "release_packager.py").read_text(encoding="utf-8")
        self.assertIn("/.superpowers/", ignored)
        self.assertIn("/docs/superpowers/", ignored)
        self.assertIn("explicit allowlist", prompt)
        self.assertIn("Do not use `git add .`", prompt)
        self.assertIn("`.superpowers/`", prompt)
        self.assertIn("`docs/superpowers/`", prompt)
        self.assertNotIn(".superpowers", package_allowlist)
        self.assertNotIn("docs/superpowers", package_allowlist)

    def test_policy_documents_contain_no_machine_specific_private_values(self):
        documents = {
            "README.md": self.zh,
            "README_EN.md": self.en,
            "SECURITY.md": self.security,
            "CHANGELOG.md": self.changelog,
            "_conf_schema.json": json.dumps(self.schema, ensure_ascii=False),
        }
        forbidden = {
            "user profile path": re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+", re.I),
            "private application path": re.compile(r"[A-Za-z]:\\qq(?:\\|$)", re.I),
            "legacy task identity": re.compile(
                "AstrBot " + "NapCat " + "Read-Only " + "Backup", re.I
            ),
            "assigned secret": re.compile(
                r"(?:api[_-]?key|token|passkey|cookie|password)\s*[:=]\s*[\"'][^\"']+[\"']",
                re.I,
            ),
        }
        for name, content in documents.items():
            for label, pattern in forbidden.items():
                with self.subTest(document=name, forbidden=label):
                    self.assertIsNone(pattern.search(content))

    def test_readme_leads_with_one_click_installation_and_setup(self):
        self.assertIn("# AstrBot 自动化安全冷备份插件", self.zh)
        self.assertIn(
            "一款面向追求绝对安全的AstrBot用户的冷备份插件，以高效且谨慎的手段备份您的敏感数据",
            self.zh,
        )
        self.assertLess(self.zh.index("## 安装与初始化"), self.zh.index("## 主要功能"))
        self.assertIn("AstrBot 插件市场", self.zh)
        self.assertIn("Release ZIP", self.zh)
        self.assertIn("/safe_backup setup", self.zh)
        self.assertIn("退出 AstrBot", self.zh)
        self.assertIn("可视终端", self.zh)
        self.assertIn("备份成功", self.zh)
        self.assertNotIn("task_command", self.zh)
        self.assertNotIn("<PYTHON_EXE>", self.zh)

    def test_readme_documents_actual_explicit_task_lifecycle(self):
        for command in ("/safe_backup task update", "/safe_backup task remove"):
            self.assertIn(command, self.zh)
        self.assertIn("卸载插件前", self.zh)
        self.assertIn("不会自动删除计划任务", self.zh)
        self.assertIn("每次实际备份尝试", self.zh)
        self.assertIn("30 秒", self.zh)
        self.assertIn("120 秒", self.zh)
        self.assertNotIn("/safe_backup task install", self.zh)

    def test_security_has_a_separate_extreme_threat_section(self):
        self.assertIn("而这些问题被认为不会在主要使用场景中出现", self.security)
        self.assertIn("不会用来隐藏普通用户容易遇到的功能缺陷", self.security)
        self.assertIn("same Windows account", self.security)
        self.assertIn("last-instruction", self.security)
        self.assertIn("external ZIP", self.security)

    def test_metadata_schema_and_changelog_match_product_contract(self):
        metadata = (ROOT / "metadata.yaml").read_text(encoding="utf-8")
        self.assertIn("display_name: AstrBot 自动化安全冷备份插件", metadata)
        self.assertIn("目前仅支持 AstrBot >=4.26,<5", metadata)
        self.assertEqual(self.schema["destination_path"]["default"], "")
        self.assertIn("/safe_backup setup", self.schema["destination_path"]["hint"])
        self.assertIn("NapCat", self.schema["napcat_enabled"]["hint"])
        self.assertIn("默认关闭", self.schema["napcat_enabled"]["hint"])
        self.assertIn("one-click", self.changelog.casefold())
        self.assertIn("visible terminal", self.changelog.casefold())

    def test_english_readme_and_publishing_prompt_match_release_contract(self):
        self.assertIn("AstrBot Automated Safe Cold Backup Plugin", self.en)
        self.assertIn("/safe_backup setup", self.en)
        self.assertNotIn("task_command", self.en)
        self.assertIn("Backup successful", self.en)
        prompt = (ROOT / "PUBLISHING_AGENT_PROMPT.md").read_text(encoding="utf-8")
        self.assertIn("astrbot_plugin_safe_backup-v0.1.0-beta.zip", prompt)
        self.assertIn("shuohui-air-technology", prompt)
        self.assertIn("stop and ask the user", prompt.casefold())

    def test_ci_compiles_release_builder_python(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('Path("scripts").glob("*.py")', ci)
        self.assertIn("python -B -", ci)

    def test_upgrade_drift_and_literal_terminal_success_are_documented(self):
        for content in (self.zh, self.en):
            self.assertIn("/safe_backup status", content)
            self.assertIn("/safe_backup task update", content)
        self.assertIn("不会自动", self.zh)
        self.assertIn("never automatically", self.en.casefold())
        self.assertIn("插件代码", self.zh)
        self.assertIn("artifact", self.en.casefold())
        self.assertIn("备份成功", self.en)
        self.assertNotIn("```text\nBackup successful\n```", self.en)


if __name__ == "__main__":
    unittest.main()
