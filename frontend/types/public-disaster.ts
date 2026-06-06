export type PublicDisaster = {
  disaster_public_uuid: string;
  event_code?: string | null;
  title: string;
  disaster_type_name?: string | null;
  severity_level?: string | null;
  disaster_status?: string | null;
  public_guidance?: string | null;
  started_at?: string | null;
  ended_at?: string | null;
};

export type PublicDisastersResponse = {
  disasters: PublicDisaster[];
};
