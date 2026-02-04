-- Quote Calculator Database Initialization
-- This script runs automatically when the PostgreSQL container is first created

-- Create extensions if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- The Flask application will create tables via SQLAlchemy
-- This file can be used for any initial data seeding or custom PostgreSQL setup

-- Grant all privileges to the application user (handled by POSTGRES_USER env var)
-- No additional setup needed as SQLAlchemy handles table creation
