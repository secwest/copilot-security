package example;

import java.io.StringWriter;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;

@Component
public final class TemplateRenderer {
    public String render(String name) {
        VelocityContext context = new VelocityContext();
        context.put("name", HtmlUtils.htmlEscape(name));
        StringWriter output = new StringWriter();
        Velocity.evaluate(context, output, "preview", "<p>Hello $name</p>");
        return output.toString();
    }
}
