require "open3"

marker = "ruby-shell-expanded"
payload = '; printf "$RUBY_COMMAND_MARKER"'
output, status = Open3.capture2e(
  { "RUBY_COMMAND_MARKER" => marker },
  "printf",
  "%s",
  payload,
)
abort "control witness command failed" unless status.success?

puts "shell_expanded_marker=#{output.include?(marker) ? 1 : 0}"
