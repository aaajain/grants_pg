//sample scripts

insert into rjhs_grants.rjhs_role_map (role_name,is_read_allowed,is_write_allowed,is_active,target_schema,target_schema_owner)
values('rjhs_read',true,false,'Y','public','rjhs_adm');

insert into rjhs_grants.rjhs_role_map (role_name,is_read_allowed,is_write_allowed,is_active,target_schema,target_schema_owner)
values('rjhs_rw',true,true,'Y','public','rjhs_adm');

insert into rjhs_grants.rjhs_role_map (role_name,is_read_allowed,is_write_allowed,is_active,target_schema,target_schema_owner)
values('rjhs_read',true,false,'Y','rjhs_etl','rjhs_adm');

insert into rjhs_grants.rjhs_role_map (role_name,is_read_allowed,is_write_allowed,is_active,target_schema,target_schema_owner)
values('rjhs_rw',true,true,'Y','rjhs_etl','rjhs_adm');


insert into rjhs_grants.rjhs_role_map (role_name,is_read_allowed,is_write_allowed,is_active,target_schema,target_schema_owner)
values('rjhs_read',true,false,'Y','rjhs_dms','rjhs_adm');

insert into rjhs_grants.rjhs_role_map (role_name,is_read_allowed,is_write_allowed,is_active,target_schema,target_schema_owner)
values('rjhs_rw',true,true,'Y','rjhs_dms','rjhs_adm');