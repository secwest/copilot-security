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
      "cover-256.jpg",
    );
    return exits.success(fs.readFileSync(filePath, "utf8"));
  },
};
