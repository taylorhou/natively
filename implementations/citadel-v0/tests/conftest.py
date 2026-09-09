from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from natively import keys
from natively.node import Node
from natively.objects import new_id


def uid(prefix: str) -> str:
    """A well-formed protocol id (<prefix>_<ULID>) for fixtures."""
    return new_id(prefix)


class Clock:
    def __init__(self, start: datetime | None = None):
        self.t = start or datetime(2026, 9, 7, 7, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.t

    def tick(self, seconds: int) -> None:
        self.t += timedelta(seconds=seconds)


def make_node(root: Path, name: str, clock: Clock, *, extensions=None, reports=None) -> Node:
    kd = root / f"{name}-keys"
    keys.generate_all(kd)
    n = Node(
        state_dir=root / f"{name}-state",
        keys_dir=kd,
        scratch_dir=root / f"{name}-scratch",
        clock=clock,
        report=(reports.append if reports is not None else None),
    )
    if extensions:
        n.config["extensions"].update(extensions)
        n.save_config()
    n.make_card(
        agent_name=name, node_name=f"{name}-node", principal_name=f"{name}-principal (stand-in)"
    )
    return n


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def node(tmp_path, clock):
    return make_node(tmp_path, "solo", clock)
