-- +goose Up
-- Normalize phone_number to E.164-like: digits only after +, 00 treated as +
-- Uses a temp column to avoid self-reference issues
UPDATE users u
SET phone_number = '+' || sub.digits
FROM (
  SELECT id,
    REGEXP_REPLACE(
      REGEXP_REPLACE(
        CASE WHEN phone_number ~ '^00' THEN SUBSTRING(phone_number FROM 3)
             WHEN phone_number ~ '^\+' THEN SUBSTRING(phone_number FROM 3)
             ELSE phone_number END,
        '[\s\-\(\)\.]', '', 'g'
      ),
      '[^0-9]', '', 'g'
    ) AS digits
  FROM users
) sub
WHERE u.id = sub.id
  AND LENGTH(sub.digits) >= 6;

-- +goose Down
-- No downgrade for data normalization
