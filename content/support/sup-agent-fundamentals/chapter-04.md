---
chapter: 4
title: "Service Issues and Outage Awareness"
part: "The Work"
---

# Service Issues and Outage Awareness

Some tickets are one customer's problem. Others are the visible edge of a
wider outage affecting many customers at once, and treating the second kind
like the first wastes everyone's time — yours, the customer's, and Network
Operations' (NOC). This chapter covers what Sub actually tracks about
outages, exactly what you can and cannot see about them from your role, and
the real, supported way to connect a ticket to a known outage.

**By the end of this chapter you can:**

- Recognise when a ticket might be part of a wider outage rather than an
  isolated fault.
- Explain why the network monitoring console is outside your access, and
  why that is by design.
- Link a ticket to a known outage correctly, so the connection is on the
  record.
- Know who to ask, and for what, when you suspect an outage but have not
  been told about one yet.

## Outages are tracked in Sub — just not by you

Sub has a real, structured record of outages: an incident against a
network node, base station, or cabinet, with its own lifecycle. Two kinds
of outage exist in that record, and it is worth knowing both exist even
though you will mostly hear about them from NOC rather than see them
yourself:

- **Operator-declared** — NOC has confirmed it from the console. Lifecycle:
  `open` → `resolved`.
- **Classifier-detected** — an automated system flags a likely outage before
  a human confirms it. Lifecycle: `suspected` → `confirmed` → `clearing` →
  `resolved` (or `discarded`, if it turns out to be a false alarm).

Each incident tracks how many customers are affected and when it started —
useful context if NOC shares it with you, and useful vocabulary if you need
to ask NOC a precise question ("is this confirmed or still suspected?")
rather than a vague one.

## The console is NOC's, not yours — and that is by design

FIGURE `SUP-04-02` *Reaching the network monitoring console without the right access.*

If you try to open the network monitoring console directly, you will see
exactly this: an access-denied page, not a bug. Your support role does not
carry `monitoring:read` — the permission that opens NOC's console — because
that console controls a different kind of risk (declaring and managing
live infrastructure incidents) that is deliberately kept with the team that
owns it. This is the same principle from Chapter 1: a missing screen is a
boundary, not an oversight, and the fix is never to find a side door
through it.

In practice, this means **you will not self-serve "is there a known
outage in this area."** Today, that information reaches you by asking NOC
directly — through whatever coordination channel your team uses — not by
checking a dashboard yourself. That is a real limitation, and a
reasonable thing to flag upward if it costs you time repeatedly; it is not
something to work around by guessing.

## What you *can* do: link the ticket

FIGURE `SUP-04-01` *Linking a ticket to its outage reference from the ticket detail screen.*

Once NOC has told you the relevant outage — typically by giving you its
reference — open the ticket and use the **Related Outage / Links** panel
to record it: paste the outage ticket's identifier and link it. This one
action is the difference between "I was told about an outage in a chat
message that will scroll away" and "this ticket carries a permanent,
visible link to the incident it belongs to."

Do this every time you learn a ticket is outage-related, even if you
already told the customer verbally. The link is what lets anyone who opens
this ticket later — another agent, a supervisor, an auditor — see the
connection without having to dig through chat history that was never meant
to be the record.

## Recognising an outage-shaped ticket

You will not always be told about an outage in advance. Watch for the
pattern instead:

- Multiple tickets arriving close together, describing the same symptom, in
  the same area or region.
- A customer reporting a total loss of service rather than a specific,
  narrow complaint.
- A ticket where the customer mentions neighbours or nearby businesses
  having the same problem.

None of these prove an outage — but any of them is a good reason to ask
NOC before you spend an hour troubleshooting one customer's equipment for
a problem that is not on their end at all.

## Common failure modes

- **Troubleshooting a single account for an area-wide problem.** Ask about a
  possible outage before assuming the fault is local to this customer.
- **Getting outage information verbally and never linking it.** If it is not
  linked on the ticket, the next person has no way to know.
- **Trying to reach the NOC console anyway** — through a bookmarked link, a
  shared login, or asking someone else to check "quickly." The access
  boundary exists for the same reason your own scoped access does.
- **Escalating every connectivity complaint as a suspected outage** without
  first checking for the pattern above. That trains NOC to discount your
  reports.

## Do this at work

1. **When you get two or more similar tickets in a short window, check for a
   common area or region before you triage them individually.**
2. **The next time you are told about an outage, link every affected ticket
   you are handling to it**, not just the first one.
3. **Practice stating what you would ask NOC**, precisely, if you suspected
   an outage — "is X confirmed" is a better question than "is something
   wrong."
4. **If you hit the access-denied page**, treat it as confirmation you are
   in the right place asking the right person, not as an obstacle to solve
   yourself.

## Practice scenarios

Illustrative situations, not real customer records.

1. Within twenty minutes you receive four tickets, all from the same
   region, all reporting "connected but can't browse." What do you do
   before triaging the fourth one the same way as the first three?
   *(This is exactly the outage-shaped pattern: same symptom, same area,
   clustered in time. Ask NOC whether there is a known or suspected
   incident before treating these as four unrelated equipment problems —
   and if NOC confirms one, link all four tickets to it, not just the one
   you are working on right now.)*

2. NOC tells you in chat that there is a confirmed outage affecting a
   cabinet, and gives you the outage ticket reference. You resolve your
   customer's call by telling them about it. What is still missing?
   *(The ticket itself does not yet reflect this. Open the ticket and use
   Related Outage / Links to record the reference — telling the customer
   is necessary but not sufficient, because it leaves no trace for anyone
   who opens the ticket later.)*

## Summary

- Sub tracks real outage incidents, operator-declared or
  classifier-detected, each with its own lifecycle — but the console that
  manages them belongs to NOC, not to your role, by design.
- You will typically learn about an outage from NOC rather than discover it
  yourself — that is a known limitation to flag, not to route around.
- The Related Outage / Links panel on a ticket is your real, supported tool:
  use it every time you learn a ticket is outage-related, so the connection
  is on the permanent record rather than only in chat.
- Watch for clustered, similar-symptom tickets as a sign to ask about an
  outage before troubleshooting each one individually.
