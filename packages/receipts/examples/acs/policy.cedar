// An ACS Guardian's policy. The action and the resource are the tool name; context.args holds the argument values the
// agent submitted (or, for a result, exit_status and outputs); context.acs.method names the hook.

// `like` matches characters, not paths: "/reports/../etc/passwd" matches "/reports/*". Refuse any `..`, and have the
// tool resolve the path as well.
@reason("reading a published report is allowed")
permit (principal, action == Action::"file_read", resource)
when {
  context.acs.method == "steps/toolCallRequest" &&
  context.args has path &&
  context.args.path like "/reports/*" &&
  !(context.args.path like "*..*")
};

// A result is tied to its request: this Guardian allowed it, for the same tool, and no result has been let through yet.
@reason("one result may reach the agent, for a file_read this Guardian allowed")
permit (principal, action == Action::"file_read", resource)
when {
  context.acs.method == "steps/toolCallResult" &&
  context.acs has requestRef &&
  context.acs.requestRef.resolved &&
  context.acs.requestRef has decision &&
  context.acs.requestRef.decision == "allow" &&
  context.acs.requestRef.tool == "file_read" &&
  !context.acs.requestRef.consumed
};
