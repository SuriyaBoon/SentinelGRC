import json
import re
import unittest
from pathlib import Path
try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    Draft202012Validator = None
    FormatChecker = None
from contract_validation import (
    CANONICAL_TEXT_PATTERN,
    is_canonical_text,
    NORMALIZED_RFC3339_PATTERN,
    RFC3339_PATTERN,
)
from portfolio_contracts import (
    ASSET_ALLOWED,
    ASSET_REQUIRED,
    EVIDENCE_REFERENCE_PATTERN,
    IDENTIFIER,
    SOURCE_IDENTIFIER_PATTERN,
    TICKET_ALLOWED,
    TICKET_REQUIRED,
    normalize_asset_context_v1,
    normalize_remediation_ticket_v1,
)
from scripts.ingestion_api import validate_posture
ROOT = Path(__file__).parent
class PortfolioContractTests(unittest.TestCase):
    @staticmethod
    def asset():
        return {
            "schema_version": "asset_context.v1",
            "source": "home-lab-v5",
            "source_asset_id": "INV-1",
            "observed_at": "2026-08-19T00:00:00Z",
            "asset_id": "WIN-01",
            "hostname": "win-01",
            "owner": "owner-01",
            "criticality": "high",
            "status": "active",
            "evidence_refs": ["sample://inventory/INV-1"],
        }
    @staticmethod
    def ticket():
        return {
            "schema_version": "remediation_ticket.v1",
            "source": "helpdesk",
            "source_ticket_id": "HD-1",
            "finding_id": "F-1",
            "asset_id": "WIN-01",
            "owner": "analyst-01",
            "status": "assigned",
            "priority": "P2",
            "created_at": "2026-08-19T00:00:00Z",
            "updated_at": "2026-08-19T00:01:00Z",
            "due_at": "2026-08-19T08:00:00Z",
            "evidence_refs": ["https://helpdesk.invalid/tickets/HD-1"],
        }
    @staticmethod
    def posture():
        return {
            "schema_version": "1.0",
            "collected_at": "2026-08-19T00:00:00Z",
            "asset_id": "WIN-01",
            "hostname": "win-01",
            "bitlocker_system_drive": True,
            "firewall_all_profiles_enabled": True,
            "defender_realtime_enabled": True,
            "days_since_last_update": 1,
            "os": "Windows",
            "os_version": "11",
            "domain": True,
            "owner": "owner-01",
            "criticality": "high",
            "checks": [
                {
                    "name": "firewall",
                    "passed": True,
                    "value": "enabled",
                    "error": None,
                }
            ],
        }
    @staticmethod
    def load_schema(name):
        return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    def test_schema_and_runtime_fields_match(self):
        asset_schema = self.load_schema("asset-context.v1.schema.json")
        ticket_schema = self.load_schema("remediation-ticket.v1.schema.json")
        self.assertEqual(set(asset_schema["properties"]), ASSET_ALLOWED)
        self.assertEqual(set(asset_schema["required"]), ASSET_REQUIRED)
        self.assertEqual(set(ticket_schema["properties"]), TICKET_ALLOWED)
        self.assertEqual(set(ticket_schema["required"]), TICKET_REQUIRED)
    def test_schema_and_runtime_share_evidence_reference_pattern(self):
        asset_schema = self.load_schema("asset-context.v1.schema.json")
        ticket_schema = self.load_schema("remediation-ticket.v1.schema.json")
        asset_pattern = asset_schema["properties"]["evidence_refs"]["items"]["pattern"]
        ticket_pattern = ticket_schema["properties"]["evidence_refs"]["items"]["pattern"]
        self.assertEqual(asset_pattern, EVIDENCE_REFERENCE_PATTERN)
        self.assertEqual(ticket_pattern, EVIDENCE_REFERENCE_PATTERN)
    def test_asset_context_is_stable_and_strict(self):
        first = normalize_asset_context_v1(self.asset())
        changed = self.asset()
        changed["criticality"] = "critical"
        second = normalize_asset_context_v1(changed)
        self.assertEqual(first["context_id"], second["context_id"])
        invalid = self.asset()
        invalid["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            normalize_asset_context_v1(invalid)
    def test_source_identity_is_canonical_and_collision_safe(self):
        for fixture, normalizer in (
            (self.asset, normalize_asset_context_v1),
            (self.ticket, normalize_remediation_ticket_v1),
        ):
            canonical = fixture()
            normalizer(canonical)
            noncanonical = fixture()
            noncanonical["source"] = canonical["source"].upper()
            with self.subTest(schema=canonical["schema_version"]):
                with self.assertRaisesRegex(ValueError, "canonical lowercase"):
                    normalizer(noncanonical)
        for schema_name in (
            "asset-context.v1.schema.json",
            "remediation-ticket.v1.schema.json",
        ):
            schema = self.load_schema(schema_name)
            self.assertEqual(
                schema["properties"]["source"]["pattern"],
                SOURCE_IDENTIFIER_PATTERN,
            )
    def test_runtime_rejects_non_rfc3339_timestamp_forms(self):
        definitions = (
            (self.asset, normalize_asset_context_v1, ("observed_at",)),
            (
                self.ticket,
                normalize_remediation_ticket_v1,
                ("created_at", "updated_at", "due_at"),
            ),
        )
        for fixture, normalizer, fields in definitions:
            for field in fields:
                for invalid_value in (
                    "2026-08-19 00:00:00+00:00",
                    "2026-08-19T00:00:00",
                    "2026-08-19t00:00:00z",
                ):
                    with self.subTest(field=field, value=invalid_value):
                        payload = fixture()
                        payload[field] = invalid_value
                        with self.assertRaises(ValueError):
                            normalizer(payload)
    def test_asset_context_rejects_bad_business_context_and_evidence(self):
        cases = (
            ("owner", "bad owner"),
            ("criticality", "urgent"),
            ("criticality", "HIGH"),
            ("status", "Active"),
            ("observed_at", "2026-08-19"),
            ("evidence_refs", ["file:///secret"]),
            ("evidence_refs", ["https:///missing-authority"]),
            ("evidence_refs", ["https://user:secret@example.invalid/evidence"]),
            ("evidence_refs", [" sample://inventory/INV-1"]),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                invalid = self.asset()
                invalid[field] = value
                with self.assertRaises(ValueError):
                    normalize_asset_context_v1(invalid)
    def test_ticket_is_stable_and_strict(self):
        first = normalize_remediation_ticket_v1(self.ticket())
        changed = self.ticket()
        changed["status"] = "in_progress"
        second = normalize_remediation_ticket_v1(changed)
        self.assertEqual(first["ticket_context_id"], second["ticket_context_id"])
        invalid = self.ticket()
        invalid["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            normalize_remediation_ticket_v1(invalid)
    def test_ticket_rejects_invalid_sla_context(self):
        cases = (
            ("priority", "P0"),
            ("priority", "p2"),
            ("status", "Assigned"),
            ("status", "deleted"),
            ("updated_at", "2026-08-18T00:00:00Z"),
            ("due_at", "naive"),
            ("due_at", "2026-08-18T00:00:00Z"),
            ("evidence_refs", ["file:///ticket"]),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                invalid = self.ticket()
                invalid[field] = value
                with self.assertRaises(ValueError):
                    normalize_remediation_ticket_v1(invalid)
    def test_ticket_allows_due_at_equal_to_created_at(self):
        ticket = self.ticket()
        ticket["due_at"] = ticket["created_at"]
        normalize_remediation_ticket_v1(ticket)  # must not raise
    def test_normalizers_reject_integer_only_keys_with_value_error(self):
        payload = {2048: "misdirected"}
        for normalizer, label in (
            (normalize_asset_context_v1, "asset context"),
            (normalize_remediation_ticket_v1, "remediation ticket"),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "field names must be strings"):
                    normalizer(payload)
    def test_normalizers_reject_mixed_string_and_integer_keys_with_value_error(self):
        for fixture, normalizer, label in (
            (self.asset, normalize_asset_context_v1, "asset context"),
            (self.ticket, normalize_remediation_ticket_v1, "remediation ticket"),
        ):
            payload = fixture()
            payload[2048] = "misdirected"
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, "field names must be strings"):
                    normalizer(payload)
    def test_posture_optional_fields_follow_schema(self):
        payload = self.posture()
        validate_posture(payload)
        for field in ("owner", "checks"):
            missing = dict(payload)
            del missing[field]
            validate_posture(missing)
        for field in ("os", "os_version", "domain", "days_since_last_update"):
            nullable = dict(payload)
            nullable[field] = None
            validate_posture(nullable)
        cases = (
            ("domain", "yes"),
            ("owner", ""),
            ("owner", None),
            ("criticality", "urgent"),
            ("days_since_last_update", -1),
            ("days_since_last_update", "1"),
            ("asset_id", "my asset 01"),
            ("checks", None),
            ("checks", [{"name": "x", "passed": "yes", "value": None, "error": None}]),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                invalid = dict(payload)
                invalid[field] = value
                with self.assertRaises(ValueError):
                    validate_posture(invalid)
    TRUST_BOUNDARY_DEFINITIONS = (
        (
            "asset-context.v1.schema.json",
            "asset-context-normalized.v1.schema.json",
            "asset",
            "normalize_asset_context_v1",
            "context_id",
            frozenset({"observed_at"}),
        ),
        (
            "remediation-ticket.v1.schema.json",
            "remediation-ticket-normalized.v1.schema.json",
            "ticket",
            "normalize_remediation_ticket_v1",
            "ticket_context_id",
            frozenset({"created_at", "updated_at", "due_at"}),
        ),
    )
    def test_input_and_normalized_schemas_share_property_definitions(self):
        for source_name, normalized_name, _, _, derived, timestamp_fields in self.TRUST_BOUNDARY_DEFINITIONS:
            source = self.load_schema(source_name)
            normalized = self.load_schema(normalized_name)
            self.assertNotIn(derived, source["properties"])
            normalized_shared = {
                key: value for key, value in normalized["properties"].items() if key != derived
            }
            self.assertEqual(set(source["properties"]), set(normalized_shared))
            for field_name, source_field in source["properties"].items():
                normalized_field = normalized_shared[field_name]
                with self.subTest(schema=source_name, field=field_name):
                    if field_name in timestamp_fields:
                        self.assertEqual(source_field["pattern"], RFC3339_PATTERN)
                        self.assertEqual(normalized_field["pattern"], NORMALIZED_RFC3339_PATTERN)
                        self.assertEqual(
                            {k: v for k, v in source_field.items() if k != "pattern"},
                            {k: v for k, v in normalized_field.items() if k != "pattern"},
                        )
                    else:
                        self.assertEqual(source_field, normalized_field)
    def test_source_cannot_set_the_server_derived_identity_field(self):
        for _, _, fixture_name, normalizer_name, derived, _ in self.TRUST_BOUNDARY_DEFINITIONS:
            fixture = getattr(self, fixture_name)
            normalizer = {
                "normalize_asset_context_v1": normalize_asset_context_v1,
                "normalize_remediation_ticket_v1": normalize_remediation_ticket_v1,
            }[normalizer_name]
            poisoned = fixture()
            poisoned[derived] = "ATTACKER-CONTROLLED"
            with self.subTest(derived=derived):
                with self.assertRaisesRegex(ValueError, "unknown fields"):
                    normalizer(poisoned)
    @unittest.skipUnless(
        Draft202012Validator is not None and FormatChecker is not None,
        "requires hash-locked jsonschema qualification dependency",
    )
    def test_input_and_normalized_schemas_enforce_trust_boundary_via_jsonschema(self):
        for source_name, normalized_name, fixture_name, normalizer_name, _derived, _ in self.TRUST_BOUNDARY_DEFINITIONS:
            fixture = getattr(self, fixture_name)
            normalizer = {
                "normalize_asset_context_v1": normalize_asset_context_v1,
                "normalize_remediation_ticket_v1": normalize_remediation_ticket_v1,
            }[normalizer_name]
            source = self.load_schema(source_name)
            normalized = self.load_schema(normalized_name)
            source_validator = Draft202012Validator(source, format_checker=FormatChecker())
            normalized_validator = Draft202012Validator(normalized, format_checker=FormatChecker())
            record = normalizer(fixture())
            with self.subTest(schema=source_name):
                self.assertEqual(list(source_validator.iter_errors(fixture())), [])
                self.assertTrue(list(source_validator.iter_errors(record)))
                self.assertEqual(list(normalized_validator.iter_errors(record)), [])
    EVIDENCE_AUTHORITY_VALID = (
        "https://example.invalid/path",
        "azblob://archive.invalid/container/blob",
        "sample://inventory/INV-1",
        "urn:sentinel:evidence:1",
    )
    EVIDENCE_AUTHORITY_INVALID = (
        "https://?evidence=1",
        "https://#fragment",
        "azblob://:443/path",
        "https://user@example.invalid/path",
        "https://user:secret@example.invalid/path",
        "https://example.invalid:0/path",
        "https://example.invalid:8443/path",
        "https://example.invalid:65535/path",
        "https://example.invalid:99999/path",
        "urn:evidence\x00id",
        "urn:evidence\x01id",
        "https://example.invalid/a\x1fb",
        "urn:evidence\x7fid",
        "urn:evidence\u200bid",
        "urn:evidence\ufeffid",
    )
    def test_evidence_authority_is_hostname_only_without_ports(self):
        for reference in self.EVIDENCE_AUTHORITY_VALID:
            with self.subTest(reference=reference):
                payload = self.asset()
                payload["evidence_refs"] = [reference]
                normalize_asset_context_v1(payload)
        for reference in self.EVIDENCE_AUTHORITY_INVALID:
            with self.subTest(reference=reference):
                payload = self.asset()
                payload["evidence_refs"] = [reference]
                with self.assertRaises(ValueError):
                    normalize_asset_context_v1(payload)
    def test_evidence_authority_pattern_matches_across_all_four_schemas(self):
        for schema_name in (
            "asset-context.v1.schema.json",
            "asset-context-normalized.v1.schema.json",
            "remediation-ticket.v1.schema.json",
            "remediation-ticket-normalized.v1.schema.json",
        ):
            schema = self.load_schema(schema_name)
            pattern = schema["properties"]["evidence_refs"]["items"]["pattern"]
            with self.subTest(schema=schema_name):
                self.assertEqual(pattern, EVIDENCE_REFERENCE_PATTERN)
    @unittest.skipUnless(
        Draft202012Validator is not None, "requires hash-locked jsonschema qualification dependency"
    )
    def test_evidence_authority_pattern_matches_runtime_via_jsonschema(self):
        definitions = (
            ("asset-context.v1.schema.json", self.asset, lambda value: value),
            (
                "asset-context-normalized.v1.schema.json",
                self.asset,
                normalize_asset_context_v1,
            ),
            ("remediation-ticket.v1.schema.json", self.ticket, lambda value: value),
            (
                "remediation-ticket-normalized.v1.schema.json",
                self.ticket,
                normalize_remediation_ticket_v1,
            ),
        )
        for schema_name, fixture, transform in definitions:
            schema = self.load_schema(schema_name)
            validator = Draft202012Validator(schema)
            valid_record = transform(fixture())
            for reference in self.EVIDENCE_AUTHORITY_VALID:
                payload = dict(valid_record)
                payload["evidence_refs"] = [reference]
                self.assertEqual(
                    list(validator.iter_errors(payload)), [], (schema_name, reference)
                )
            for reference in self.EVIDENCE_AUTHORITY_INVALID:
                payload = dict(valid_record)
                payload["evidence_refs"] = [reference]
                self.assertTrue(
                    list(validator.iter_errors(payload)), (schema_name, reference)
                )
    def test_canonical_text_rejects_controls_and_boundary_whitespace(self):
        invalid = (
            " leading",
            "trailing ",
            "\u00a0leading",
            "trailing\u2003",
            "\u2028leading",
            "trailing\u2029",
            "win\x0001",
            "win\t01",
            "win\n01",
            "win\x7f01",
        )
        for value in invalid:
            with self.subTest(value=repr(value)):
                payload = self.asset()
                payload["hostname"] = value
                with self.assertRaises(ValueError):
                    normalize_asset_context_v1(payload)
                posture = self.posture()
                posture["os"] = value
                with self.assertRaises(ValueError):
                    validate_posture(posture)
        payload = self.asset()
        payload["hostname"] = "Windows workstation"
        self.assertEqual(
            normalize_asset_context_v1(payload)["hostname"],
            "Windows workstation",
        )
    def test_posture_exploit_payload_is_rejected(self):
        payload = self.posture()
        payload["collected_at"] = "2026-08-19 00:00:00+00:00"
        payload["os"] = "Windows\n11"
        payload["checks"][0]["name"] = "fire\nwall"
        with self.assertRaises(ValueError):
            validate_posture(payload)
    def test_posture_schema_and_runtime_share_text_and_timestamp_contracts(self):
        schema = self.load_schema("posture.schema.json")
        self.assertEqual(schema["properties"]["collected_at"]["pattern"], RFC3339_PATTERN)
        for name in ("hostname", "os", "os_version", "owner"):
            self.assertEqual(schema["properties"][name]["pattern"], CANONICAL_TEXT_PATTERN)
        self.assertEqual(schema["properties"]["asset_id"]["pattern"], f"^{IDENTIFIER.pattern}$")
        check_properties = schema["properties"]["checks"]["items"]["properties"]
        self.assertEqual(check_properties["name"]["pattern"], CANONICAL_TEXT_PATTERN)
        self.assertEqual(check_properties["error"]["pattern"], CANONICAL_TEXT_PATTERN)
        for field, value in (
            ("os", "Windows\n11"),
            ("owner", " owner"),
        ):
            payload = self.posture()
            payload[field] = value
            with self.assertRaises(ValueError):
                validate_posture(payload)
        for field, value in (("name", "fire\nwall"), ("error", "bad\x7ferror")):
            payload = self.posture()
            payload["checks"][0][field] = value
            with self.assertRaises(ValueError):
                validate_posture(payload)
    @unittest.skipUnless(
        Draft202012Validator is not None, "requires hash-locked jsonschema qualification dependency"
    )
    def test_posture_schema_rejects_the_exploit_payload_via_jsonschema(self):
        schema = self.load_schema("posture.schema.json")
        validator = Draft202012Validator(schema)
        exploit = self.posture()
        exploit["collected_at"] = "2026-08-19 00:00:00+00:00"
        exploit["os"] = "Windows\n11"
        exploit["checks"][0]["name"] = "fire\nwall"
        self.assertTrue(list(validator.iter_errors(exploit)))
    @unittest.skipUnless(
        Draft202012Validator is not None and FormatChecker is not None,
        "requires hash-locked jsonschema qualification dependency",
    )
    def test_schema_date_time_formats_are_executable(self):
        definitions = (
            ("asset-context.v1.schema.json", self.asset, ("observed_at",)),
            (
                "remediation-ticket.v1.schema.json",
                self.ticket,
                ("created_at", "updated_at", "due_at"),
            ),
        )
        for schema_name, fixture, fields in definitions:
            schema = self.load_schema(schema_name)
            validator = Draft202012Validator(
                schema,
                format_checker=FormatChecker(),
            )
            for field in fields:
                self.assertEqual(schema["properties"][field]["pattern"], RFC3339_PATTERN)
            self.assertEqual(list(validator.iter_errors(fixture())), [])
            for field in fields:
                for invalid_value in (
                    "not-a-timestamp",
                    "2026-08-19T00:00:00",
                    "2026-08-19 00:00:00+00:00",
                    "2026-08-19t00:00:00z",
                ):
                    with self.subTest(schema=schema_name, field=field, value=invalid_value):
                        invalid = fixture()
                        invalid[field] = invalid_value
                        self.assertTrue(list(validator.iter_errors(invalid)))
    @unittest.skipUnless(
        Draft202012Validator is not None and FormatChecker is not None,
        "requires hash-locked jsonschema qualification dependency",
    )
    def test_schema_format_assertion_rejects_impossible_calendar_values(self):
        impossible = "2026-99-99T99:99:99Z"
        self.assertIsNotNone(re.fullmatch(RFC3339_PATTERN, impossible))
        for schema_name, field in (
            ("asset-context.v1.schema.json", "observed_at"),
            ("remediation-ticket.v1.schema.json", "created_at"),
        ):
            schema = self.load_schema(schema_name)
            field_schema = schema["properties"][field]
            without_format_assertion = Draft202012Validator(field_schema)
            with_format_assertion = Draft202012Validator(
                field_schema, format_checker=FormatChecker()
            )
            with self.subTest(schema=schema_name, field=field):
                self.assertEqual(list(without_format_assertion.iter_errors(impossible)), [])
                self.assertTrue(list(with_format_assertion.iter_errors(impossible)))
        payload = self.asset()
        payload["observed_at"] = impossible
        with self.assertRaises(ValueError):
            normalize_asset_context_v1(payload)
    def test_canonical_text_rejects_c1_controls(self):
        for control in ("\u0085", "\u009f"):
            with self.subTest(control=repr(control)):
                self.assertFalse(is_canonical_text(f"win{control}11", 128))

    def test_canonical_text_rejects_bom_and_zero_width_space(self):
        for character in ("\ufeff", "\u200b"):
            with self.subTest(character=ord(character)):
                asset = self.asset()
                asset["hostname"] = character + "win-01"
                with self.assertRaises(ValueError):
                    normalize_asset_context_v1(asset)

    def test_canonical_text_rejects_unicode_line_and_paragraph_separators(self):
        # U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) are
        # matched by \s at the string's edges, so a value like "\u2028win"
        # or "win\u2028" was already rejected. The gap was the *interior*
        # body character class, which excluded specific control/format
        # characters but not these two - so "win\u202801" (the character
        # sitting in the middle) slipped through and could split a log
        # line or report row unexpectedly.
        for character in ("\u2028", "\u2029"):
            with self.subTest(character=hex(ord(character))):
                # Edge positions (already covered, kept here for completeness)
                for value in (character + "win-01", "win-01" + character):
                    asset = self.asset()
                    asset["hostname"] = value
                    with self.assertRaises(ValueError):
                        normalize_asset_context_v1(asset)
                # Interior position - this is the exact reported gap
                interior = "win" + character + "01"
                asset = self.asset()
                asset["hostname"] = interior
                with self.assertRaises(ValueError):
                    normalize_asset_context_v1(asset)
                posture = self.posture()
                posture["os"] = interior
                with self.assertRaises(ValueError):
                    validate_posture(posture)
                evidence_asset = self.asset()
                evidence_asset["evidence_refs"] = [
                    f"sample://inventory/INV{character}1"
                ]
                with self.assertRaises(ValueError):
                    normalize_asset_context_v1(evidence_asset)

    def test_equivalent_timestamp_offsets_normalize_to_utc(self):
        first = self.asset()
        second = self.asset()
        second["observed_at"] = "2026-08-19T07:00:00+07:00"
        self.assertEqual(
            normalize_asset_context_v1(first)["observed_at"],
            normalize_asset_context_v1(second)["observed_at"],
        )

    def test_timestamp_fraction_precision_is_bounded_at_runtime(self):
        definitions = (
            (self.asset, normalize_asset_context_v1, ("observed_at",)),
            (
                self.ticket,
                normalize_remediation_ticket_v1,
                ("created_at", "updated_at", "due_at"),
            ),
        )
        for fixture, normalizer, fields in definitions:
            for field in fields:
                for fraction, valid in (
                    ("", True),
                    (".1", True),
                    (".000001", True),
                    (".0000001", False),
                    (".1234567", False),
                ):
                    with self.subTest(field=field, fraction=fraction):
                        payload = fixture()
                        payload[field] = f"2026-08-19T00:00:00{fraction}Z"
                        if valid:
                            normalizer(payload)
                        else:
                            with self.assertRaises(ValueError):
                                normalizer(payload)
        for fraction, valid in (
            ("", True),
            (".1", True),
            (".000001", True),
            (".0000001", False),
        ):
            with self.subTest(field="collected_at", fraction=fraction):
                posture = self.posture()
                posture["collected_at"] = f"2026-08-19T00:00:00{fraction}Z"
                if valid:
                    validate_posture(posture)
                else:
                    with self.assertRaises(ValueError):
                        validate_posture(posture)

    def test_all_five_schemas_bound_timestamp_precision_in_parallel_with_runtime(self):
        definitions = (
            ("asset-context.v1.schema.json", ("observed_at",), RFC3339_PATTERN),
            (
                "asset-context-normalized.v1.schema.json",
                ("observed_at",),
                NORMALIZED_RFC3339_PATTERN,
            ),
            ("posture.schema.json", ("collected_at",), RFC3339_PATTERN),
            (
                "remediation-ticket.v1.schema.json",
                ("created_at", "updated_at", "due_at"),
                RFC3339_PATTERN,
            ),
            (
                "remediation-ticket-normalized.v1.schema.json",
                ("created_at", "updated_at", "due_at"),
                NORMALIZED_RFC3339_PATTERN,
            ),
        )
        for schema_name, fields, expected_pattern in definitions:
            schema = self.load_schema(schema_name)
            for field in fields:
                pattern = schema["properties"][field]["pattern"]
                with self.subTest(schema=schema_name, field=field):
                    self.assertEqual(pattern, expected_pattern)
                    for fraction, accepted in (
                        ("", True),
                        (".1", True),
                        (".000001", True),
                        (".0000001", False),
                        (".12345678", False),
                    ):
                        value = f"2026-08-19T00:00:00{fraction}Z"
                        self.assertEqual(
                            re.fullmatch(pattern, value) is not None,
                            accepted,
                            value,
                        )
                    if expected_pattern == RFC3339_PATTERN:
                        self.assertIsNotNone(
                            re.fullmatch(pattern, "2026-08-19T00:00:00.000001+07:00")
                        )
                    else:
                        self.assertIsNone(
                            re.fullmatch(pattern, "2026-08-19T00:00:00.000001+07:00")
                        )

    def test_sub_microsecond_ordering_collapse_is_rejected(self):
        # datetime.fromisoformat() truncates fractions beyond six digits, so
        # these two distinct instants would compare equal as datetimes; the
        # bounded profile rejects the payload before that collapse can hide
        # the ordering difference.
        payload = self.ticket()
        payload["created_at"] = "2026-08-19T00:00:00.0000009Z"
        payload["updated_at"] = "2026-08-19T00:00:00.0000001Z"
        with self.assertRaisesRegex(ValueError, "is invalid"):
            normalize_remediation_ticket_v1(payload)
if __name__ == "__main__":
    unittest.main()
