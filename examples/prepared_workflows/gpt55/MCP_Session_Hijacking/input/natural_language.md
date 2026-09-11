### Session Hijacking

Session hijacking is an attack vector where a client is provided a
session ID by the server, and an unauthorized party is able to obtain
and use that same session ID to impersonate the original client and
perform unauthorized actions on their behalf.

#### Attack Description

When you have multiple stateful HTTP servers that handle MCP requests,
the following attack vectors are possible:

**Session Hijack Prompt Injection**

1. The client connects to **Server A** and receives a session ID.
1. The attacker obtains an existing session ID and sends a malicious
   event to **Server B** with said session ID.
   - When a server supports
     [redelivery/resumable streams](/specification/2025-06-18/basic/transports#resumability-and-redelivery),
     deliberately terminating the request before receiving the response
     could lead to it being resumed by the original client via the GET
     request for server sent events.
   - If a particular server initiates server sent events as a
     consequence of a tool call such as a
     `notifications/tools/list_changed`, where it is possible to affect
     the tools that are offered by the server, a client could end up
     with tools that they were not aware were enabled.

1. **Server B** enqueues the event (associated with session ID) into a
   shared queue.
1. **Server A** polls the queue for events using the session ID and
   retrieves the malicious payload.
1. **Server A** sends the malicious payload to the client as an
   asynchronous or resumed response.
1. The client receives and acts on the malicious payload, leading to
   potential compromise.

**Session Hijack Impersonation**

1. The MCP client authenticates with the MCP server, creating a
   persistent session ID.
2. The attacker obtains the session ID.
3. The attacker makes calls to the MCP server using the session ID.
4. MCP server does not check for additional authorization and treats the
   attacker as a legitimate user, allowing unauthorized access or
   actions.

#### Mitigation

To prevent session hijacking and event injection attacks, the following
mitigations should be implemented:

MCP servers that implement authorization **MUST** verify all inbound
requests. MCP Servers **MUST NOT** use sessions for authentication.

MCP servers **MUST** use secure, non-deterministic session IDs.
Generated session IDs (e.g., UUIDs) **SHOULD** use secure random number
generators. Avoid predictable or sequential session identifiers that
could be guessed by an attacker. Rotating or expiring session IDs can
also reduce the risk.

MCP servers **SHOULD** bind session IDs to user-specific information.
When storing or transmitting session-related data (e.g., in a queue),
combine the session ID with information unique to the authorized user,
such as their internal user ID. Use a key format like
`<user_id>:<session_id>`. This ensures that even if an attacker guesses
a session ID, they cannot impersonate another user as the user ID is
derived from the user token and not provided by the client.

MCP servers can optionally leverage additional unique identifiers.

