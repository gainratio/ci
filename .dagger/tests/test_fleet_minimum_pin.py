"""Required-minimum floors for central Dagger module pins."""

from __future__ import annotations

import pytest

from ci.fleet_policy import (
    REQUIRED_MINIMUM,
    DaggerConfig,
    PinAncestry,
    validate_minimum_pins,
)

FLOOR = "dd19871486588b1582e432b7bc1f2cfffb296340"
NEWER = "9d491851" + "0" * 32
OLDER = "1963264" + "0" * 33
FOUNDATION = "github.com/hseshadr/ci/modules/portfolio-foundation@"


def _config(identity: str) -> DaggerConfig:
    path = identity.partition("hseshadr/ci/")[2].rpartition("@")[0] + "/dagger.json"
    return DaggerConfig(identity=identity, path=path, name="shared", engine_version="v0.21.8")


def _codes(pin: str, *ancestry: PinAncestry) -> tuple[str, ...]:
    configs = (_config(FOUNDATION + pin),)
    return tuple(item.code for item in validate_minimum_pins(configs, ancestry))


def test_should_floor_foundation_at_rerun_skew_fix_when_reviewed() -> None:
    # Given the reviewed mandatory fix hseshadr/ci#46 (dd19871)
    # Then the floor is that exact literal commit and no other module has one
    assert dict(REQUIRED_MINIMUM) == {"portfolio-foundation": FLOOR}


def test_should_accept_pin_when_equal_to_floor() -> None:
    # Given a consumer pinned exactly at the floor, which is on main
    evidence = PinAncestry(floor=FLOOR, pin=FLOOR, floor_status="identical", main_status="ahead")

    # When the floor is evaluated, then no finding is reported
    assert _codes(FLOOR, evidence) == ()


def test_should_accept_pin_when_descended_from_floor() -> None:
    # Given a consumer pinned at a main commit newer than the floor
    evidence = PinAncestry(floor=FLOOR, pin=NEWER, floor_status="ahead", main_status="identical")

    # When the floor is evaluated, then no finding is reported
    assert _codes(NEWER, evidence) == ()


def test_should_reject_pin_when_older_than_floor() -> None:
    # Given a consumer pinned at a main commit that predates the mandatory fix
    evidence = PinAncestry(floor=FLOOR, pin=OLDER, floor_status="behind", main_status="ahead")

    # Then the stale release gate is a failing finding
    assert _codes(OLDER, evidence) == ("pin-below-required-minimum",)


@pytest.mark.parametrize(
    ("floor_status", "main_status"),
    [("ahead", "diverged"), ("diverged", "diverged"), ("unrelated", "unrelated")],
)
def test_should_reject_pin_when_off_main_or_unrelated(floor_status: str, main_status: str) -> None:
    # Given a pin on an unmerged branch, a diverged branch, or unrelated history
    pin = "e" * 40
    evidence = PinAncestry(floor=FLOOR, pin=pin, floor_status=floor_status, main_status=main_status)

    # Then it cannot satisfy the floor
    assert _codes(pin, evidence) == ("pin-below-required-minimum",)


def test_should_fail_closed_when_ancestry_evidence_is_absent() -> None:
    # Given a floored module pin whose ancestry was never read
    # Then the missing evidence is itself the finding
    assert _codes("e" * 40) == ("pin-below-required-minimum",)


def test_should_ignore_module_when_it_has_no_floor() -> None:
    # Given a central module with no reviewed floor and no ancestry evidence
    configs = (_config("github.com/hseshadr/ci/modules/unknown-module@" + "e" * 40),)

    # Then there is nothing to compare and no finding
    assert validate_minimum_pins(configs, ()) == ()


def test_should_ignore_config_when_consumer_owned() -> None:
    # Given the consumer's own root config shares the module directory name
    config = DaggerConfig(
        identity="github.com/hseshadr/example/modules/portfolio-foundation@" + "e" * 40,
        path="modules/portfolio-foundation/dagger.json",
        name="example",
        engine_version="v0.21.8",
    )

    # Then only hseshadr/ci modules are floored
    assert validate_minimum_pins((config,), ()) == ()
