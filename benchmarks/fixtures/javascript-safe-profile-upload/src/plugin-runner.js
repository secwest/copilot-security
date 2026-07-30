import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export async function activatePlugins(applicationRoot, application) {
  const pluginDirectory = join(applicationRoot, "plugins");
  for (const name of await readdir(pluginDirectory)) {
    if (!name.endsWith(".mjs")) continue;
    const location = pathToFileURL(join(pluginDirectory, name)).href;
    const plugin = await import(location);
    await plugin.activate(application);
  }
}
