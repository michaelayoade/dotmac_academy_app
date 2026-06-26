CREATE ROLE app_admin LOGIN BYPASSRLS PASSWORD 'app_admin';
CREATE ROLE app_user LOGIN PASSWORD 'app_user';
CREATE ROLE platform_api LOGIN PASSWORD 'platform_api';
GRANT ALL ON SCHEMA public TO app_admin;
