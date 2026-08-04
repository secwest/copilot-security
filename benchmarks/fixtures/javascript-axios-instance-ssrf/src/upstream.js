import axios from "axios";

const client = axios.create({
  baseURL: "https://preview.example.internal/api/",
  maxRedirects: 5,
  timeout: 2_000,
});

export async function fetchPreview(target, response) {
  const upstream = await client.get(target);
  return response.send(upstream.data);
}
