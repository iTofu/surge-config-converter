"""Tests for Surge v5+ → v4 configuration converter."""

import os
import textwrap

import pytest

from converter import (
    ConversionStats,
    backup_if_exists,
    comment_line,
    convert_content,
    convert_file,
    extract_proxy_type,
    make_v4_filename,
    remove_proxy_params,
    transform_proxy_line,
    transform_rule_line,
    transform_general_line,
)


# --- Helpers ---

def convert(text, base_dir="/tmp", stats=None, processed_files=None):
    """Shorthand for convert_content with defaults."""
    if stats is None:
        stats = ConversionStats()
    if processed_files is None:
        processed_files = set()
    return convert_content(textwrap.dedent(text).strip(), base_dir, stats, processed_files)


# --- T1: Proxy protocol commenting ---

class TestProxyProtocolCommenting:
    def test_hysteria2_commented(self):
        result = convert("""
            [Proxy]
            US-HY2 = hysteria2, 1.2.3.4, 443, password=pwd, download-bandwidth=100
        """)
        assert "# [v5+] US-HY2 = hysteria2" in result

    def test_hy2_shorthand_commented(self):
        result = convert("""
            [Proxy]
            US-HY2 = hy2, 1.2.3.4, 443, password=pwd
        """)
        assert "# [v5+] US-HY2 = hy2" in result

    def test_anytls_commented(self):
        result = convert("""
            [Proxy]
            JP-ANYTLS = anytls, 5.6.7.8, 443, password=pwd
        """)
        assert "# [v5+] JP-ANYTLS = anytls" in result

    def test_tuic_commented(self):
        result = convert("""
            [Proxy]
            SG-TUIC = tuic, 9.10.11.12, 443, token=pwd, alpn=h3
        """)
        assert "# [v5+] SG-TUIC = tuic" in result

    def test_supported_protocols_unchanged(self):
        input_text = textwrap.dedent("""
            [Proxy]
            US-SNELL = snell, 1.2.3.4, 8000, psk=password, version=4
            HK-TROJAN = trojan, 1.2.3.4, 443, password=pwd
            JP-SS = ss, 1.2.3.4, 8000, encrypt-method=chacha20-ietf-poly1305, password=pwd
            US-VMESS = vmess, 1.2.3.4, 8000, username=uuid-here
        """).strip()
        result = convert(input_text)
        # None should be commented
        for line in result.splitlines():
            if line.startswith("["):
                continue
            assert not line.startswith("# [v5+]"), f"Should not be commented: {line}"

    def test_mixed_protocols(self):
        result = convert("""
            [Proxy]
            US-HY2 = hysteria2, 1.2.3.4, 443, password=pwd, download-bandwidth=100
            US-SNELL = snell, 1.2.3.4, 8000, psk=password, version=4
            JP-ANYTLS = anytls, 5.6.7.8, 443, password=pwd
            SG-TUIC = tuic, 9.10.11.12, 443, token=pwd, alpn=h3
            HK-TROJAN = trojan, 1.2.3.4, 443, password=pwd
        """)
        lines = result.splitlines()
        assert lines[1].startswith("# [v5+]")  # hysteria2
        assert not lines[2].startswith("# [v5+]")  # snell
        assert lines[3].startswith("# [v5+]")  # anytls
        assert lines[4].startswith("# [v5+]")  # tuic
        assert not lines[5].startswith("# [v5+]")  # trojan


# --- T2: Snell version=5 → version=4 ---

class TestSnellVersion:
    def test_version5_to_4(self):
        result = convert("""
            [Proxy]
            US-SNELL = snell, x.com, 27443, psk=xxx, version=5, tfo=true
        """)
        assert "version=4" in result
        assert "version=5" not in result

    def test_version4_unchanged(self):
        result = convert("""
            [Proxy]
            US-SNELL = snell, x.com, 27443, psk=xxx, version=4, tfo=true
        """)
        assert "version=4" in result

    def test_stats_counted(self):
        stats = ConversionStats()
        convert("""
            [Proxy]
            S1 = snell, x.com, 1, psk=a, version=5
            S2 = snell, y.com, 2, psk=b, version=5
        """, stats=stats)
        assert stats.params_modified == 2


# --- T3: shadow-tls-version=3 → 2 ---

class TestShadowTls:
    def test_version3_to_2(self):
        result = convert("""
            [Proxy]
            US-SS = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, password=pwd, shadow-tls-version=3, shadow-tls-password=stpwd
        """)
        assert "shadow-tls-version=2" in result
        assert "shadow-tls-version=3" not in result
        assert "shadow-tls-password=stpwd" in result


# --- T4: Remove port-hopping / ecn parameters ---

class TestRemoveV5Params:
    def test_port_hopping_removed_on_supported_proxy(self):
        """For a v4-supported proxy type, v5+ only params should be stripped."""
        stats = ConversionStats()
        result = convert("""
            [Proxy]
            SS1 = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, password=pwd, port-hopping="5000-6000", port-hopping-interval=30
        """, stats=stats)
        assert "port-hopping" not in result
        assert "SS1 = ss" in result

    def test_ecn_removed_on_supported_proxy(self):
        stats = ConversionStats()
        result = convert("""
            [Proxy]
            SNELL1 = snell, 1.2.3.4, 8000, psk=pwd, version=4, ecn=true
        """, stats=stats)
        assert "ecn=" not in result
        assert "SNELL1 = snell" in result

    def test_v5plus_proxy_with_v5plus_params_just_commented(self):
        """v5+ only proxy types are fully commented, params don't matter."""
        result = convert("""
            [Proxy]
            HY2 = hysteria2, 1.2.3.4, 443, password=pwd, port-hopping="5000-6000", ecn=true
        """)
        assert result.splitlines()[1].startswith("# [v5+]")


# --- T5: smart → url-test ---

class TestSmartToUrlTest:
    def test_smart_replaced(self):
        result = convert("""
            [Proxy Group]
            Auto = smart, policy-path=proxies.conf, interval=300
        """)
        assert "= url-test," in result
        assert "smart" not in result

    def test_select_unchanged(self):
        result = convert("""
            [Proxy Group]
            Manual = select, DIRECT, Proxy
        """)
        assert "= select," in result

    def test_multiple_smart_groups(self):
        result = convert("""
            [Proxy Group]
            Auto = smart, include-all-proxies=1, interval=300
            Region-HK = smart, include-all-proxies=1, policy-regex-filter=(HK|Hong Kong), hidden=true
        """)
        assert result.count("url-test") == 2
        assert "smart" not in result


# --- T6: v5+ only rule types ---

class TestV5OnlyRules:
    def test_hostname_type_commented(self):
        result = convert("""
            [Rule]
            HOSTNAME-TYPE,IPv4,Proxy
        """)
        assert "# [v5+] HOSTNAME-TYPE" in result

    def test_domain_wildcard_commented(self):
        result = convert("""
            [Rule]
            DOMAIN-WILDCARD,*.test?.com,Proxy
        """)
        assert "# [v5+] DOMAIN-WILDCARD" in result

    def test_supported_rules_unchanged(self):
        result = convert("""
            [Rule]
            DOMAIN-SUFFIX,example.com,DIRECT
            GEOIP,CN,DIRECT
            FINAL,Proxy,dns-failed
        """)
        for line in result.splitlines():
            if line.startswith("["):
                continue
            assert not line.startswith("# [v5+]")

    def test_mixed_rules(self):
        result = convert("""
            [Rule]
            DOMAIN-SUFFIX,example.com,DIRECT
            HOSTNAME-TYPE,IPv4,Proxy
            DOMAIN-WILDCARD,*.test?.com,Proxy
            GEOIP,CN,DIRECT
        """)
        lines = result.splitlines()
        assert not lines[1].startswith("# [v5+]")  # DOMAIN-SUFFIX
        assert lines[2].startswith("# [v5+]")  # HOSTNAME-TYPE
        assert lines[3].startswith("# [v5+]")  # DOMAIN-WILDCARD
        assert not lines[4].startswith("# [v5+]")  # GEOIP


# --- T7: [General] v5+ only parameters ---

class TestGeneralParams:
    def test_udp_priority_commented(self):
        result = convert("""
            [General]
            loglevel = notify
            udp-priority = true
            dns-server = 119.29.29.29
        """)
        assert "# [v5+] udp-priority = true" in result
        assert "loglevel = notify" in result
        assert "dns-server = 119.29.29.29" in result

    def test_block_quic_commented(self):
        result = convert("""
            [General]
            block-quic = all-proxy
        """)
        assert "# [v5+] block-quic = all-proxy" in result

    def test_supported_params_unchanged(self):
        result = convert("""
            [General]
            loglevel = notify
            dns-server = 119.29.29.29
            skip-proxy = localhost
        """)
        for line in result.splitlines():
            if line.startswith("[") or not line.strip():
                continue
            assert not line.startswith("# [v5+]")


# --- T8: [Port Forwarding] / [Body Rewrite] full section commenting ---

class TestV5OnlySections:
    def test_port_forwarding_commented(self):
        result = convert("""
            [Rule]
            FINAL,Proxy

            [Port Forwarding]
            0.0.0.0:6841 localhost:3306 policy=SQL-Proxy
            0.0.0.0:8080 localhost:80

            [MITM]
            hostname = *.example.com
        """)
        lines = result.splitlines()
        # Find Port Forwarding section
        pf_idx = next(i for i, l in enumerate(lines) if "Port Forwarding" in l)
        assert lines[pf_idx] == "# [v5+] [Port Forwarding]"
        assert lines[pf_idx + 1].startswith("# [v5+]")
        assert lines[pf_idx + 2].startswith("# [v5+]")
        # MITM section should not be commented
        mitm_idx = next(i for i, l in enumerate(lines) if "MITM" in l)
        assert lines[mitm_idx] == "[MITM]"
        assert "hostname = *.example.com" in result

    def test_body_rewrite_commented(self):
        result = convert("""
            [Body Rewrite]
            http-response ^https://api.example.com jq '.data'
        """)
        assert "# [v5+] [Body Rewrite]" in result
        assert "# [v5+] http-response" in result

    def test_empty_lines_in_v5plus_section_preserved(self):
        result = convert("""
            [Port Forwarding]
            line1

            line2
        """)
        lines = result.splitlines()
        assert lines[0] == "# [v5+] [Port Forwarding]"
        assert lines[1] == "# [v5+] line1"
        assert lines[2] == ""  # empty line not commented
        assert lines[3] == "# [v5+] line2"


# --- T9: #!include path update + recursive conversion ---

class TestIncludeDirective:
    def test_include_paths_updated(self, tmp_path):
        # Create referenced files
        proxies = tmp_path / "proxies.conf"
        proxies.write_text(
            "HY2-US = hysteria2, 1.2.3.4, 443, password=pwd\n"
            "SNELL-JP = snell, 5.6.7.8, 8000, psk=xxx, version=5\n"
            "TROJAN-HK = trojan, 9.10.11.12, 443, password=pwd\n"
        )
        extra = tmp_path / "extra.dconf"
        extra.write_text("SS1 = ss, 1.2.3.4, 8000, encrypt-method=aes-256-gcm, password=pwd\n")

        # Create main file
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include proxies.conf, extra.dconf\n")

        stats = ConversionStats()
        processed = {str(main)}
        output = convert_file(str(main), stats, processed)

        # Check main output
        main_v4 = tmp_path / "main-v4.conf"
        assert main_v4.exists()
        content = main_v4.read_text()
        assert "#!include proxies-v4.conf, extra-v4.dconf" in content

        # Check proxies-v4.conf
        proxies_v4 = tmp_path / "proxies-v4.conf"
        assert proxies_v4.exists()
        p_content = proxies_v4.read_text()
        assert "# [v5+] HY2-US = hysteria2" in p_content
        assert "version=4" in p_content
        assert "version=5" not in p_content
        assert "TROJAN-HK = trojan" in p_content

        # Check extra-v4.dconf
        extra_v4 = tmp_path / "extra-v4.dconf"
        assert extra_v4.exists()

    def test_include_with_nonexistent_file(self, tmp_path):
        """References to nonexistent files should still update path names."""
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include missing.conf\n")

        stats = ConversionStats()
        processed = {str(main)}
        convert_file(str(main), stats, processed)

        content = (tmp_path / "main-v4.conf").read_text()
        assert "#!include missing-v4.conf" in content


# --- T10: policy-path local path update (skip HTTP URLs) ---

class TestPolicyPath:
    def test_local_path_updated(self, tmp_path):
        local_proxies = tmp_path / "local-proxies.conf"
        local_proxies.write_text("T1 = trojan, 1.2.3.4, 443, password=pwd\n")

        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy Group]\n"
            "Proxy = select, policy-path=local-proxies.conf\n"
        )

        stats = ConversionStats()
        processed = {str(main)}
        convert_file(str(main), stats, processed)

        content = (tmp_path / "main-v4.conf").read_text()
        assert "policy-path=local-proxies-v4.conf" in content

    def test_http_url_unchanged(self):
        result = convert("""
            [Proxy Group]
            Auto = smart, policy-path=https://sub.example.com/surge.conf, interval=300
        """)
        assert "policy-path=https://sub.example.com/surge.conf" in result
        assert "url-test" in result  # smart should still be converted

    def test_mixed_local_and_http(self, tmp_path):
        local = tmp_path / "home.dconf"
        local.write_text("S1 = snell, 1.2.3.4, 8000, psk=x, version=4\n")

        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy Group]\n"
            "Proxy = select, policy-path=home.dconf\n"
            "Auto = smart, policy-path=https://sub.example.com/surge.conf, interval=300\n"
        )

        stats = ConversionStats()
        processed = {str(main)}
        convert_file(str(main), stats, processed)

        content = (tmp_path / "main-v4.conf").read_text()
        assert "policy-path=home-v4.dconf" in content
        assert "policy-path=https://sub.example.com/surge.conf" in content


# --- T11: Output file conflict backup ---

class TestBackup:
    def test_existing_output_backed_up(self, tmp_path):
        main = tmp_path / "output.conf"
        main.write_text("[General]\nloglevel = notify\n")

        # Create existing output
        existing = tmp_path / "output-v4.conf"
        existing.write_text("old content")

        stats = ConversionStats()
        processed = {str(main)}
        convert_file(str(main), stats, processed)

        # New file should exist
        assert existing.exists()
        assert existing.read_text() != "old content"

        # Backup file should exist
        backups = list(tmp_path.glob("output-v4-*.conf"))
        assert len(backups) == 1
        assert backups[0].read_text() == "old content"

    def test_no_backup_when_no_conflict(self, tmp_path):
        main = tmp_path / "output.conf"
        main.write_text("[General]\nloglevel = notify\n")

        stats = ConversionStats()
        processed = {str(main)}
        convert_file(str(main), stats, processed)

        backups = list(tmp_path.glob("output-v4-*.conf"))
        assert len(backups) == 0


# --- T12: Already-commented lines not double-processed ---

class TestAlreadyCommented:
    def test_commented_line_unchanged(self):
        result = convert("""
            [Proxy]
            # HY2-OLD = hysteria2, 1.2.3.4, 443, password=pwd
            SNELL-US = snell, 1.2.3.4, 8000, psk=xxx, version=4
        """)
        lines = result.splitlines()
        assert lines[1] == "# HY2-OLD = hysteria2, 1.2.3.4, 443, password=pwd"
        assert not lines[1].startswith("# [v5+]")

    def test_commented_rule_unchanged(self):
        result = convert("""
            [Rule]
            # HOSTNAME-TYPE,IPv4,Proxy
            DOMAIN-SUFFIX,example.com,DIRECT
        """)
        assert "# HOSTNAME-TYPE" in result
        assert "# [v5+]" not in result


# --- T13: No-op for pure v4 config ---

class TestNoOp:
    def test_pure_v4_config_unchanged(self):
        input_text = textwrap.dedent("""
            [General]
            loglevel = notify
            dns-server = 119.29.29.29

            [Proxy]
            HK-TROJAN = trojan, 1.2.3.4, 443, password=pwd
            US-SS = ss, 5.6.7.8, 8000, encrypt-method=chacha20-ietf-poly1305, password=pwd

            [Proxy Group]
            Proxy = select, HK-TROJAN, US-SS
            Auto = url-test, HK-TROJAN, US-SS, interval=300

            [Rule]
            DOMAIN-SUFFIX,example.com,DIRECT
            GEOIP,CN,DIRECT
            FINAL,Proxy
        """).strip()
        stats = ConversionStats()
        result = convert(input_text, stats=stats)
        assert result == input_text
        assert stats.lines_commented == 0
        assert stats.params_modified == 0


# --- T14: Conversion summary ---

class TestConversionSummary:
    def test_stats_tracking(self):
        stats = ConversionStats()
        convert("""
            [General]
            udp-priority = true
            block-quic = all

            [Proxy]
            HY2 = hysteria2, 1.2.3.4, 443, password=pwd
            SNELL = snell, 1.2.3.4, 8000, psk=pwd, version=5
            ANYTLS = anytls, 5.6.7.8, 443, password=pwd

            [Proxy Group]
            Auto = smart, interval=300

            [Rule]
            HOSTNAME-TYPE,IPv4,Proxy
            DOMAIN-WILDCARD,*.test.com,DIRECT
        """, stats=stats)
        # Commented: udp-priority, block-quic, HY2, ANYTLS, HOSTNAME-TYPE, DOMAIN-WILDCARD = 6
        assert stats.lines_commented == 6
        # Modified: version=5→4, smart→url-test = 2
        assert stats.params_modified == 2


# --- Utility function tests ---

class TestMakeV4Filename:
    def test_conf(self):
        assert make_v4_filename("/path/to/home.conf") == "/path/to/home-v4.conf"

    def test_dconf(self):
        assert make_v4_filename("/path/to/self-vps.dconf") == "/path/to/self-vps-v4.dconf"

    def test_relative(self):
        assert make_v4_filename("proxies.conf") == "proxies-v4.conf"


class TestExtractProxyType:
    def test_standard(self):
        assert extract_proxy_type("US-HY2 = hysteria2, 1.2.3.4, 443") == "hysteria2"

    def test_with_emoji(self):
        assert extract_proxy_type("🇺🇸 US = snell, x.com, 443, psk=x, version=4") == "snell"

    def test_commented(self):
        # Commented lines should not match
        assert extract_proxy_type("# US = hysteria2, 1.2.3.4, 443") is None

    def test_no_equals(self):
        assert extract_proxy_type("some random line") is None


class TestCommentLine:
    def test_basic(self):
        assert comment_line("some line") == "# [v5+] some line"


class TestRemoveProxyParams:
    def test_remove_single(self):
        line = "X = ss, 1.2.3.4, 8000, password=pwd, ecn=true"
        result, count = remove_proxy_params(line, {"ecn"})
        assert "ecn" not in result
        assert count == 1

    def test_remove_multiple(self):
        line = 'X = tuic, 1.2.3.4, 443, token=pwd, port-hopping="5000-6000", port-hopping-interval=30, ecn=true'
        result, count = remove_proxy_params(line, {"port-hopping", "port-hopping-interval", "ecn"})
        assert "port-hopping" not in result
        assert "ecn" not in result
        assert count == 3

    def test_no_match(self):
        line = "X = ss, 1.2.3.4, 8000, password=pwd"
        result, count = remove_proxy_params(line, {"ecn"})
        assert result == line
        assert count == 0
