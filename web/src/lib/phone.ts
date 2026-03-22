/**
 * E.164 phone number validation: + followed by 8–15 digits
 */
const E164_REGEX = /^\+\d{8,15}$/;

export function isValidE164(phone: string): boolean {
  return E164_REGEX.test(phone.trim());
}
