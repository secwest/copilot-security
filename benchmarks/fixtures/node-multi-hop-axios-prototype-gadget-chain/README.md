# Multi-hop Axios prototype-gadget chain

An Express JSON object crosses three relative-import wrappers into vulnerable Lodash 4.17.10 recursive merge. A `constructor.prototype.proxy` object then survives as shared process state until an Axios 1.17.0 request. Axios first creates null-prototype configuration, but the same official instance has a request interceptor that returns `{ ...config }`, restoring `Object.prototype`; the outbound request can inherit the attacker proxy and expose its absolute URL, authorization material, or body.

The dependency-free witness isolates all consequential transitions: an object-valued global prototype write, loss of the null-prototype boundary, absence of an own `proxy` control, inherited proxy selection, protected request material reaching that proxy, and cleanup. The scanner must separately prove the exact official bindings, vulnerable release stages, package boundary, request-to-merge flow, interceptor receiver, and later Axios call.
