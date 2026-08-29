const fs = require("node:fs");
const path = require("node:path");

module.exports = {
  inputs: {
    filename: { type: "string", required: true },
  },

  async fn(inputs, exits) {
    const filePath = path.join(
      __dirname,
      "../../../data/thumbnails",
      inputs.filename,
    );
    return exits.success(fs.readFileSync(filePath, "utf8"));
  },
};
