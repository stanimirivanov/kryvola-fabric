-- Broker receipt and application handling are independent. Existing receipts
-- are eligible for SQL reconciliation because their handling was not recorded.
ALTER TABLE fabric_inbox ADD COLUMN handled boolean NOT NULL DEFAULT false;
