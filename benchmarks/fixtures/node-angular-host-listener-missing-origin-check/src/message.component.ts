import { Component, HostListener } from "@angular/core";

@Component({ selector: "app-message-bridge", template: "" })
export class MessageBridgeComponent {
  lastAction = "";

  @HostListener("window:message", ["$event"])
  handleMessage(event: MessageEvent) {
    this.lastAction = event.data.action;
  }
}
