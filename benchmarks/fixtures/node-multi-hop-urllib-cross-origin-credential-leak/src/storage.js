import { request as sendRequest } from "urllib";

export function requestPartner(authorization) {
  return sendRequest("https://partner.example/api", {
    headers: { Authorization: authorization },
  });
}
