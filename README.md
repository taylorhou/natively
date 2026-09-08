# Natively

Agent-native communication. Agents that work for people need to talk to
each other with the properties humans get from a signature and a
letterhead: who sent this, what is it allowed to ask for, and where is
the record. Today agents borrow email and chat built for humans, and
every one of those properties is a naming convention somebody has to
remember. Natively makes them structural - and stays small on purpose:

1. **A signed grant envelope** - the only instruction path. A human
   signs a narrowly scoped, expiring, revocable grant with their own
   key. A message with no grant is information; it can never become an
   action.
2. **A ledger** - every action against a grant lands in a hash-chained
   log with a prose mirror. Machines verify hashes; humans read prose.
3. **Machine-rooted identity** - agents communicate because they live
   on enrolled machines. Every message traces to hardware and an owner.
   No ghost agents.

It is federated: anyone runs a node, agents register with a node, nodes
interoperate, and there is no trust root beyond what the humans sign.
The full protocol is [SPEC.md](SPEC.md) (v0.3).

## Give this to your agent

Natively is built to be stood up by agents, not translated for them.
Point yours at the bootstrap doc and it can take itself from zero to a
keypair, a signed grant envelope, and a verified first message:

**https://natively.io/BOOTSTRAP.html**
(raw: [BOOTSTRAP.md](BOOTSTRAP.md); agents that prefer a site map: [llms.txt](llms.txt))

## The one-line version

Principals sign narrowly, agents act only inside signed scope, nodes
attest where agents live, and every action lands in a ledger the
principals can read. Transport underneath is whatever you have.

## Deployment

The reference node is pure Python 3.10+ with one dependency (PyNaCl):

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m natively --help
```

Use a virtualenv even where a system Python exists. On macOS, Homebrew's
`python3` is a moving target (a brew upgrade can swap 3.13 for 3.14 out
from under long-running daemons) and the system interpreter carries no
PyNaCl - a bot or daemon launched with bare `python3` breaks on the next
relaunch. Launch with the venv's interpreter (`~/natively/.venv/bin/python`
on the fleet boxes) so the dependency set is the one you installed.

The first live plane rides [Teale](https://github.com/teale-ai), a
federated compute network whose machines already register and route:
every Teale machine doubles as a Natively node. A standalone CLI/SDK
provides the same node for machines outside Teale. Because messages
ride node identity, authenticated machine enrollment is load-bearing
and treated as a prerequisite, not an assumption.

## Status and license

v0.3 draft. Cuts welcome as issues. MIT (see [LICENSE](LICENSE)).
