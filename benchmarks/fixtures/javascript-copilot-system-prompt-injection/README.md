# Copilot SDK system-prompt injection

An HTTP query value crosses two local module boundaries and is interpolated into the `systemMessage.content` passed to an exact GitHub Copilot SDK session. The request therefore changes trusted instructions before the separately framed user message is sent, allowing it to redirect tool use and disclosure under the service's session authority.
