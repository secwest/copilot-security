package example;

import java.io.StringWriter;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.springframework.stereotype.Component;

@Component
public final class TemplateRenderer {
    public String render(String template) {
        StringWriter output = new StringWriter();
        Velocity.evaluate(new VelocityContext(), output, "preview", template);
        return output.toString();
    }
}
