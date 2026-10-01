import { anthropic } from "@ai-sdk/anthropic";
import type { LanguageModel } from "ai";

// The model is chosen on the server, never by the browser. The test replaces
// this function with a scripted mock model.
export const models = {
  chat: (): LanguageModel => anthropic("claude-sonnet-5-5"),
};
