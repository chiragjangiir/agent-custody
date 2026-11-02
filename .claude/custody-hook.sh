#!/bin/sh
# On a machine set up for it, every tool call an agent makes in a Claude Code session here becomes a signed receipt,
# with its hash committed to our tenant on the hosted log within seconds. The receipts, the key, and
# the log token live outside the repository in ~/.config/agent-custody; a machine without that directory is simply
# not recording, and this hook exits quietly so contributors are not affected. See https://agent-custody.dev/custody.
[ -x "$HOME/.config/agent-custody/hook.sh" ] || exit 0
exec "$HOME/.config/agent-custody/hook.sh"
