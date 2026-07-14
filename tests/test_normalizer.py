"""Normalizer: the transport boundary.

Every shape a collector might send has to land as a correct Event, because a
field that normalizes wrong is a rule that silently never fires.
"""

from __future__ import annotations

from backend.engine.normalizer import normalize


class TestPayloadShapes:
    def test_winlogbeat_envelope(self) -> None:
        event = normalize(
            {
                "winlog": {
                    "event_id": 1,
                    "computer_name": "WS01",
                    "event_data": {"Image": r"C:\W\cmd.exe", "ProcessGuid": "{g}"},
                },
            }
        )
        assert event.event_id == 1
        assert event.host == "WS01"
        assert event.image == r"C:\W\cmd.exe"
        assert event.process_guid == "{g}"

    def test_flat_payload(self) -> None:
        """The shape a developer curls by hand during rule work."""
        event = normalize(
            {"EventID": 1, "Image": r"C:\W\cmd.exe", "ParentImage": r"C:\O\WINWORD.EXE"}
        )
        assert event.event_id == 1
        assert event.parent_image == r"C:\O\WINWORD.EXE"

    def test_host_from_ecs_style_object(self) -> None:
        event = normalize(
            {"winlog": {"event_id": 1, "event_data": {}}, "host": {"name": "LAPTOP-7"}}
        )
        assert event.host == "LAPTOP-7"

    def test_missing_host_defaults_rather_than_crashing(self) -> None:
        assert (
            normalize({"winlog": {"event_id": 3, "event_data": {}}}).host == "unknown"
        )


class TestFieldHandling:
    def test_unmapped_fields_are_reachable_via_raw(self) -> None:
        """EventID 10 fields aren't promoted to attributes, but a rule must still
        be able to address them through Event.get()."""
        event = normalize(
            {
                "winlog": {
                    "event_id": 10,
                    "event_data": {
                        "TargetImage": r"C:\W\lsass.exe",
                        "GrantedAccess": "0x1410",
                    },
                }
            }
        )
        assert event.get("TargetImage") == r"C:\W\lsass.exe"
        assert event.get("GrantedAccess") == "0x1410"

    def test_non_numeric_pid_is_dropped_not_fatal(self) -> None:
        """A malformed PID must never drop the whole event -- it isn't
        load-bearing anywhere."""
        event = normalize(
            {
                "winlog": {
                    "event_id": 1,
                    "event_data": {"Image": "cmd.exe", "ProcessId": "not-a-number"},
                }
            }
        )
        assert event.process_id is None
        assert event.image == "cmd.exe"

    def test_malformed_event_id_becomes_zero(self) -> None:
        assert (
            normalize({"winlog": {"event_id": "bad", "event_data": {}}}).event_id == 0
        )


class TestSourceProcessFields:
    """EventID 8/10 name the acting process with Source* fields. The actor must
    be captured so the correlator can attach the access to the right process and
    the console can show who did it, not just an anonymous handle."""

    def test_process_access_source_becomes_the_actor(self) -> None:
        """A real Sysmon ProcessAccess event uses SourceProcessGUID (uppercase)
        and SourceImage. The acting process (mimikatz) must land in image/guid."""
        event = normalize(
            {
                "winlog": {
                    "event_id": 10,
                    "event_data": {
                        "SourceProcessGUID": "{src}",
                        "SourceImage": r"C:\Tools\mimikatz.exe",
                        "TargetImage": r"C:\Windows\system32\lsass.exe",
                        "GrantedAccess": "0x1010",
                    },
                }
            }
        )
        assert event.image == r"C:\Tools\mimikatz.exe"
        assert event.process_guid == "{src}"
        # the target stays reachable in raw for rules
        assert event.get("TargetImage") == r"C:\Windows\system32\lsass.exe"

    def test_lowercase_guid_variant_also_works(self) -> None:
        """Some collectors normalize the field to SourceProcessGuid."""
        event = normalize(
            {
                "winlog": {
                    "event_id": 10,
                    "event_data": {
                        "SourceProcessGuid": "{src}",
                        "SourceImage": r"C:\x.exe",
                    },
                }
            }
        )
        assert event.process_guid == "{src}"

    def test_normal_process_creation_still_prefers_image(self) -> None:
        """An EventID 1 event has Image and no Source*, and must be unaffected."""
        event = normalize(
            {
                "winlog": {
                    "event_id": 1,
                    "event_data": {
                        "Image": r"C:\W\cmd.exe",
                        "ProcessGuid": "{g}",
                    },
                }
            }
        )
        assert event.image == r"C:\W\cmd.exe"
        assert event.process_guid == "{g}"
