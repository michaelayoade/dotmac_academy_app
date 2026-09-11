---
chapter: 3
title: "Reading a Customer: Status, Service, and Bandwidth"
part: "The Work"
---

# Reading a Customer: Status, Service, and Bandwidth

"Is this customer active?" sounds like a one-field question. It is not.
Sub tracks a customer's **account status**, their **service/subscription
status**, and their **connection state** as three separate things that can
each say something different at the same moment — and misreading which one
answers the question you were actually asked is one of the most common
ways a support call goes sideways. This chapter teaches you to read a
customer record correctly.

**By the end of this chapter you can:**

- Tell the difference between account status and service status, and know
  which one answers which question.
- Read a customer's plan and bandwidth correctly.
- Explain why a customer can be "active" and still offline — or vice versa.
- Navigate a customer record without needing to ask someone else first.

FIGURE `SUP-03-02` *The Customers directory: search, filter, and open an account.*

## Two different status fields, on purpose

The **account** (the subscriber relationship itself) has its own status,
independent of any one service: `new`, `active`, `blocked`, `suspended`,
`disabled`, `canceled`, `delinquent`. This is the "is this person a
customer in good standing" answer.

Each individual **subscription** (the specific service they are paying
for) has its *own*, separately-tracked status: `pending`, `active`,
`blocked`, `suspended`, `stopped`, `disabled`, `hidden`, `archived`,
`canceled`, `expired`.

These are not the same field shown twice. A customer's account can be
`active` while one specific subscription on that account is `suspended` —
for instance, a business customer with two lines where only one has an
overdue balance. Always check the level the customer is actually asking
about: "is my account okay" is an account-status question; "why is my
internet not working" is almost always a subscription- or
connection-level question.

## Plan and bandwidth

FIGURE `SUP-03-01` *A customer's account overview: status, plan, balance, and connection.*

A customer's plan (their `CatalogOffer`) is where the bandwidth numbers
live — download and upload speed — bundled with the price. When a customer
asks "what speed am I paying for," you are reading the plan, not the
account status. When they ask "why is it slow," bandwidth-as-sold is your
starting reference point, not proof of what they are actually getting
right now — that is a network diagnostic question, which is out of scope
for this course and belongs with the technical/network team.

## Connection: a third, live-er signal

The account overview also shows a **connection** indicator (online /
offline). This reflects whether the account currently has an active
network session — not whether it is entitled to one. An account can be
fully `active`, on a fully `active` subscription, and still show
**offline** — for example, the customer's equipment is powered off, or
they simply are not connected right now. Offline is not, by itself,
evidence of a fault. It becomes relevant when the customer says they
*expect* to be connected and are not.

Put the three together in that order — account status, subscription
status, connection state — and you can answer almost any "what's going on
with this customer" question precisely, instead of guessing from one
number.

## Finding the account

Use **Customers → search** by name, email, phone, account number, or
PPPoE identifier — whichever the customer gives you first. Once open, the
account page is organized into tabs: **Account** (the overview you have
just learned to read), **Service**, **Network**, **Billing**, **Tickets**,
**Timeline**. You do not need to master every tab in this course — knowing
that Tickets and Timeline exist on the customer record itself, not only
inside Support, is often the fastest way to see everything that has ever
happened to this customer in one place.

## Common failure modes

- **Reading "active" and stopping there.** Active *what* — the account, or
  the specific service the customer is asking about? They can disagree.
- **Treating "offline" as a fault report.** It is a live state, not a
  verdict. Ask what the customer expects before treating it as a problem.
- **Quoting the plan's bandwidth as a guarantee of current speed.** It is
  what they are sold, not a live measurement.
- **Guessing instead of opening the account.** Every one of these questions
  has a real answer on screen — look before you speculate.

## Do this at work

1. **Open five different customer accounts** and, for each, state out loud:
   account status, one subscription's status, and the connection
   indicator. Notice how often they do not all say the same thing.
2. **Practice restating a customer's question** in terms of which of the
   three levels it is actually about, before you look anything up.
3. **Find a customer whose account and subscription status differ**, if one
   exists in your queue, and understand why.
4. **Locate the Tickets and Timeline tabs** on a customer record you already
   know, and compare what you see there with what Support search shows for
   the same customer.

## Practice scenarios

Illustrative situations, not real customer records.

1. A customer calls: "My account is active, I can see that in the app, but
   the internet doesn't work." What are the two most likely places to look
   next, and in which order?
   *(Check the specific subscription's status first — the "account" a
   customer sees in a self-service app is often the account-level status,
   which can be active while the relevant subscription is suspended for
   non-payment. Only after confirming the subscription is genuinely active
   does "offline" become a real connectivity question rather than an
   entitlement one.)*

2. A brand-new customer signed up yesterday and has no subscription showing
   yet. They call asking why their service "isn't active." Is this
   necessarily a problem?
   *(Not necessarily — a brand-new account can legitimately have no
   subscription yet if installation or activation has not completed. Check
   what stage the account is actually at before treating it as a fault; the
   answer here is about process status, not troubleshooting.)*

3. An overdue-balance customer calls annoyed that their connection is
   offline. What do you check, and what do you tell them?
   *(Check whether the subscription itself has moved to a
   payment-related status such as `blocked`, `suspended`, or `delinquent`
   at the account level. If so, the offline connection is a direct,
   correctly-working consequence of the billing state, not a fault — and
   the honest, useful answer to the customer is about resolving the
   balance, not "let me check the network.")*

## Summary

- Account status, subscription status, and connection state are three
  separate signals — read all three before answering a "what's going on"
  question.
- Plan and bandwidth live on the subscription's offer; they describe what
  was sold, not a live measurement.
- Offline is a live state, not automatically a fault — check what the
  customer expects before treating it as one.
- Customer search takes name, email, phone, account number, or PPPoE ID;
  the account record's own Tickets and Timeline tabs are often the fastest
  way to see full history in one place.
