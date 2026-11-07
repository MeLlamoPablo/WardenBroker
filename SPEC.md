# WardenBroker

- Like https://github.com/MeLlamoPablo/secrets-broker-workers
- Mobile-first PWA supporting notifications
- UI extremely simplified compared to `secrets-broker-workers`, we reimplement the concepts
- Must run on CloudFlare Workers

## Security Model

- Everything is sent in plaintext to the agent. We trust agents to make a responsible use of the secrets and not load them into context, but ultimately this out of WardenBroker's control and can be mitigated by Zero Data Retention combined with OpenRouter's server side prompt redaction. We will not have the complexity of implementing browser fill.
- Broker never holds plaintext secrets. They are send e2ee to the agent, and decrypted from Bitwarden 

### User Registration

- User sets up PWA (don't allow running in non PWA mode)
- User authenticates with the bitwarden master password (usually on phone)
- User sets up a passkey to quickly login thereafter
  - Passkey encrypts master password and it's stored locally (is this possible?)
- User accepts notifications

### Agent Registration

- Agent registers itself with the CLI, gives itself a name
  - Under the hood this generates a public key for the agent
- User gets a notification and authorizes request

### Secret Exchange

- Agent requests a secret for a host and gives a reason
- User gets a notification
- Secret for matching host is auto picked. If none (or multiple) available, user picks
- User authorizes for a given amount of time, or permanently
- User sends to broker secret encrypted with the agent's public key
  - Broker holds encrypted secret for however long the user authorized
  - For that time, the agent can access the secret immediately without authorization
- Broker responds to agent with the secret
  - Q: can we hold the agent's request whilst keeping the <10ms cpu time requirement of CloudFlare Workers free? If not, we may need to have the agent's CLI poll the broker

## Dead Simple UI

- When there is something to be authorized, the user sees the authorization.
- Otherwise, we just show connected agents and logs. Nothing else.

## CloudFlare Workers Free tier

This whole project must be able to run in the free tier of CloudFlare Workers end-to-end, so we must adhere to the <10ms CPU time limit at all times!

## Stack

- Server side: I'm not opinionated here. Pick the fastest stack that can run on CF Workers. e.g go if it's an option.
- Client side: also not opinionated, if it's easy we can just SSR from whatever fast stack we have. But if it's too complicated (e.g. we need to build our in-house html templating, etc) we can always do a traditional dead simple React SPA (in fact that's probably better for a PWA?)
- CLI: also a fast compiled language, probably go
