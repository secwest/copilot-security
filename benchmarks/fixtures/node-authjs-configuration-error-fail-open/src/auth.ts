import NextAuth from "next-auth";

export const { auth } = NextAuth({
  providers: [
    {
      id: "deployment-oidc",
      name: "Deployment OIDC",
      type: "oidc",
      clientId: "deployment-client",
      clientSecret: "deployment-secret",
    },
  ],
});
