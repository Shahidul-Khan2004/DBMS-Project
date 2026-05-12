import { MessageBanner } from "@/components/ui/StatusState";

export function ErrorAlert({ message }: { message: string }) {
  return (
    <MessageBanner tone="error" title="Something went wrong">
      {message}
    </MessageBanner>
  );
}
