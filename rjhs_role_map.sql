CREATE TABLE rjhs_grants.rjhs_role_map (
      rjhs_role_map_id SERIAL PRIMARY KEY,
      role_name VARCHAR(100) NOT NULL,
      is_read_allowed BOOLEAN NOT NULL,
      is_write_allowed BOOLEAN NOT NULL,
      is_active char(1) DEFAULT 'Y',
      target_schema VARCHAR(100),
      target_schema_owner VARCHAR(100),
      created_by VARCHAR(100) DEFAULT current_user,
                  created_date TIMESTAMP DEFAULT NOW(),
      modified_by VARCHAR(100) DEFAULT current_user,
      modified_date TIMESTAMP DEFAULT NOW()                                                                                                                                
);
