// Starter policy for `agent-custody init claude-code`.
// The policy permits every call and forbids a short list of destructive Bash commands.
// A pattern matches the text of the command. It is not a sandbox: it catches the plain form of each command.
// Each rule has a `@reason`. The hook shows it to the agent and to the person who reads the session.
// The `like` operator is case-sensitive, and `*` is its only wildcard, so each SQL keyword has a rule for each case.
permit(principal, action, resource);

// Rewriting shared history.
// `--force-with-lease` is a force push that fails when the remote has new commits. The policy allows it.
// A `--force` flag matches anywhere after `git push`. A `-f` flag matches right after `git push` or at the end of the
// command. A `-f` in the middle of a command is not matched, because `git push origin main && rm -f x` must pass.
@reason("force push rewrites shared history (git push --force-with-lease is allowed)")
forbid(principal, action == Action::"Bash", resource)
when {
  context.args has command && (
    context.args.command like "*git push*--force *"
    || context.args.command like "*git push*--force"
    || context.args.command like "*git push -f*"
    || context.args.command like "*git push* -f"
  )
};

// Deleting the root directory or the home directory.
@reason("rm -rf on the root directory")
forbid(principal, action == Action::"Bash", resource)
when {
  context.args has command && (
    context.args.command like "*rm -rf /"
    || context.args.command like "*rm -rf / *"
    || context.args.command like "*rm -rf /\*"
    || context.args.command like "*rm -fr /"
    || context.args.command like "*rm -fr / *"
    || context.args.command like "*rm -fr /\*"
  )
};

@reason("rm -rf on the home directory")
forbid(principal, action == Action::"Bash", resource)
when {
  context.args has command && (
    context.args.command like "*rm -rf ~"
    || context.args.command like "*rm -rf ~ *"
    || context.args.command like "*rm -rf ~/"
    || context.args.command like "*rm -rf ~/ *"
    || context.args.command like "*rm -rf ~/\*"
    || context.args.command like "*rm -fr ~"
    || context.args.command like "*rm -fr ~ *"
    || context.args.command like "*rm -fr ~/"
    || context.args.command like "*rm -fr ~/ *"
    || context.args.command like "*rm -fr ~/\*"
  )
};

@reason("rm -rf on the home directory")
forbid(principal, action == Action::"Bash", resource)
when {
  context.args has command && (
    context.args.command like "*rm -rf $HOME"
    || context.args.command like "*rm -rf $HOME *"
    || context.args.command like "*rm -rf $HOME/"
    || context.args.command like "*rm -rf $HOME/ *"
    || context.args.command like "*rm -rf $HOME/\*"
    || context.args.command like "*rm -fr $HOME"
    || context.args.command like "*rm -fr $HOME *"
    || context.args.command like "*rm -fr $HOME/"
    || context.args.command like "*rm -fr $HOME/ *"
    || context.args.command like "*rm -fr $HOME/\*"
    || context.args.command like "*rm -rf ${HOME}"
    || context.args.command like "*rm -rf ${HOME} *"
    || context.args.command like "*rm -rf ${HOME}/"
    || context.args.command like "*rm -rf ${HOME}/ *"
    || context.args.command like "*rm -rf ${HOME}/\*"
    || context.args.command like "*rm -fr ${HOME}"
    || context.args.command like "*rm -fr ${HOME} *"
    || context.args.command like "*rm -fr ${HOME}/"
    || context.args.command like "*rm -fr ${HOME}/ *"
    || context.args.command like "*rm -fr ${HOME}/\*"
  )
};

// Destroying infrastructure or a database.
@reason("terraform destroy deletes infrastructure")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*terraform destroy*" };

@reason("terraform apply -destroy deletes infrastructure")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*terraform apply* -destroy*" };

@reason("drop database deletes a database")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*drop database*" };

@reason("drop database deletes a database")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*DROP DATABASE*" };
