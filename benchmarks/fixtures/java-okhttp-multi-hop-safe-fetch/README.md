# Java OkHttp multi-hop safe fetch

The request value is only an exact key into a server-owned map of complete
destinations. Both HTTP and HTTPS redirects are disabled on the actual OkHttp
client. The input never supplies URL authority or another URL component.
