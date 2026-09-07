# Natively

Agent-native communication. Agents that work for people need to talk to
each other with the same properties humans get from a signature and a
letterhead: who sent this, what is it allowed to ask for, and where is
the record. Today they borrow email, chat, and ticket systems built for
humans, and every one of those properties is a naming convention
somebody has to remember.

Natively is the small layer that makes them structural. It is not a
transport and it does not compete with one. It is three things:

1. **A signed grant envelope** - the only instruction path. A principal
   (a human, holding their own key) signs a narrowly scoped, expiring,
   revocable grant. A message with no grant is information; it can never
   become an action. This is mechanical, not social.
2. **A ledger convention** - every action taken against a grant is
   appended to a hash-chained log with a prose mirror. Machines verify
   hashes; principals read prose.
3. **Machine-rooted identity** - an agent communicates natively only
   because it lives on a machine that runs a Natively node. Agent
   identity derives from node identity; node identity derives from
   machine enrollment. Every message traces to hardware and an owner.
   No ghost agents.

The specification is [SPEC.md](SPEC.md). It is at v0.2 and small on
purpose.

## Architecture: federated nodes

Natively is federated, the way email and Matrix are federated: anyone
can run a node, agents register with a node, and nodes interoperate.
There is no central operator and no trust root beyond what the humans
sign. A node:

- enrolls as a machine (a host key, bound to the machine's owner);
- vouches for the agents resident on it;
- routes messages to other nodes and verifies what arrives;
- keeps its share of the ledger, reconciled by exchanging head hashes.

What a node vouches for is residency, not humanity. A node attests that
an agent lives on a real enrolled machine - which stops casual spoofing
and makes "where did this come from" answerable. It does not prove a
human is behind anything, and it does not try: virtual machines count
as machines, and a determined farm passes residency the way it passes
most checks. That limit is stated, not hidden.

## Deployment: Teale machines as the plane

The first deployment rides [Teale](https://github.com/teale-ai), a
federated compute network whose machines already register, heartbeat,
and route through a relay. Every Teale machine doubles as a Natively
communication node: the existing node identity and registration become
the message plane, so any agent on any Teale box gets native
communication for free, and every new supply machine is automatically a
comms node. A standalone CLI/SDK provides the same node for machines
that are not part of Teale.

Because messages will flow over node identity, authenticated
registration is load-bearing for the message plane. A registry that
accepts anyone's word is a spoofing machine the moment messages ride
it; enrollment has to be real before the plane goes live.

## The one-line version

Principals sign narrowly, agents act only inside signed scope, nodes
attest where agents live, and every action lands in a ledger the
principals can read. Transport underneath is whatever you have.

## Status

v0.2 draft. Converged between two operating agent deployments with
different stacks and different principals. The open items are tracked in
the spec. Discussion and cuts welcome as issues.

## License

MIT (see [LICENSE](LICENSE)).
