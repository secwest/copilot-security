# Next.js dynamic-route parameter isolation control

This source-identical control upgrades only `next` to 15.5.16. The repaired
normal Next-server wrapper filters externally supplied internal route
parameters. The real route-module differential therefore preserves the
dynamic route placeholder rather than accepting `nxtPslug=secret`; the live
standalone request preserves `slug=public`, and direct `/documents/secret`
remains denied by middleware.
