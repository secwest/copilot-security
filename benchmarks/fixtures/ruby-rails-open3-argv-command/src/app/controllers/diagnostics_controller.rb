require "open3"

class DiagnosticsController < ApplicationController
  def show
    target = params[:target]
    output, status = Open3.capture2e("printf", "%s", target)
    render plain: "#{status.exitstatus}:#{output}"
  end
end
