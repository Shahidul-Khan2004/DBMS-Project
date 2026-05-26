export interface NotificationItem {
  notification_recipient_id: number;
  notification_id: number;
  notification_type: string;
  title: string;
  body: string;
  entity_type: string | null;
  entity_id: number | null;
  delivery_channel: "in_app" | string;
  read_at: string | null;
  created_at: string;
}

export interface NotificationsResponse {
  notifications: NotificationItem[];
}

export interface UnreadCountResponse {
  unreadCount: number;
}
