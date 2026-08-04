import axios from "axios";

const ASSET_URLS = Object.freeze({
  logo: "/assets/logo.svg",
  theme: "/assets/theme.css",
});

const client = axios.create({
  baseURL: "https://assets.example.internal/api/",
  allowAbsoluteUrls: false,
  maxRedirects: 0,
  timeout: 2_000,
});

export async function fetchPreview(asset, response) {
  if (!Object.hasOwn(ASSET_URLS, asset)) return response.status(404).end();
  const upstream = await client.get(ASSET_URLS[asset]);
  return response.send(upstream.data);
}
