import { readThumbnail } from "../../../services/thumbnail-reader.js";

export default {
  inputs: {
    filename: { type: "string", required: true },
  },

  async fn(inputs, exits) {
    const selected = inputs.filename;
    return exits.success(readThumbnail(selected));
  },
};
