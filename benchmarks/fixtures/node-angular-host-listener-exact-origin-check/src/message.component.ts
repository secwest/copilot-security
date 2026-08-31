import { Component, HostListener } from "@angular/core";

@Component({ selector: "app-message-bridge", template: "" })
export class MessageBridgeComponent {
  lastAction = "";

  @HostListener("window:message", ["$event"])
  handleMessage(event: MessageEvent) {
    if (event.origin !== "https://portal.example") return;
    this.lastAction = event.data.action;
  }
}
