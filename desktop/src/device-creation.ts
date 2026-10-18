import type { Dashboard } from "./app-api";

/** A completed, activated draft is archived by the backend before a new key.
 * Pending or unconfirmed drafts must stay protected against duplicate creation. */
export function canCreateDevice(data:Pick<Dashboard,"account"|"device_draft"|"public_key">, busy:boolean):boolean {
  if(busy || !data.account.authenticated || data.account.devices.length>=5)return false;
  const draft=data.device_draft;
  return !draft || draft.state==="prepared" || (draft.state==="created" && draft.public_key===data.public_key);
}
