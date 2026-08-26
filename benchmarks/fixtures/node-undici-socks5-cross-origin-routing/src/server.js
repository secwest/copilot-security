import { Socks5ProxyAgent, request } from "undici";

const proxy = new Socks5ProxyAgent(process.env.SOCKS_PROXY);

export async function proxyThenLoadAccount(req) {
  await request(req.query.previewUrl, { dispatcher: proxy });
  return request("https://billing.internal/account", {
    dispatcher: proxy,
    headers: { authorization: process.env.BILLING_TOKEN },
  });
}
