import { publicGet } from "@/lib/api";
import type { PublicDisastersResponse } from "@/types/public-disaster";

export async function listPublicDisasters(): Promise<PublicDisastersResponse> {
  const data = await publicGet<PublicDisastersResponse>("/public/disasters");

  return {
    ...data,
    disasters: Array.isArray(data.disasters) ? data.disasters : [],
  };
}
