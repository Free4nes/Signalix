/**
 * User/contact objects that have display_name and phone_number
 */
export type UserOrContact = {
  display_name?: string | null;
  phone_number: string;
};

export function displayLabel(userOrContact: UserOrContact | null | undefined): string {
  if (!userOrContact) return "";
  const dn = userOrContact.display_name?.trim();
  if (dn) return dn;
  return userOrContact.phone_number || "";
}
