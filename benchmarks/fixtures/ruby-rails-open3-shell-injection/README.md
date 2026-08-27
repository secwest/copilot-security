# Rails Open3 shell-command injection

This fixture models a Rails controller that reads `params[:host]` and embeds it
in the one-string form of `Open3.capture2e`. Ruby may pass this form through a
command shell, so shell metacharacters in the request value can alter command
grammar.

`witness.rb` uses a harmless environment marker and proves that a semicolon in
the payload causes the shell to execute a second `printf`. It performs no file,
network, persistence, credential, or privilege operation.
