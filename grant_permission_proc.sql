create or replace function rjhs_grants.grant_permission()
returns integer as $status$
declare 
    res json;
    t json;
    tname varchar[];
	seqname varchar[];
	funname varchar[];
    target_schema text;
    target_owner text;
    tblname text;
    sqname text;
    fname text;
    is_write text;
    is_read text;
    role_name text;
    is_table varchar;
    login_user text;
    length int;
begin
    begin
    	select to_regclass('rjhs_grants.permission_logs') into is_table;
		select current_user into login_user; 
        raise notice 'is_table % ',is_table;
        raise notice 'login_user % ',login_user;
        if is_table is not null then
	       	truncate table rjhs_grants.permission_logs;
            raise notice 'truncate table % ',is_table;
        else
        	create table rjhs_grants.permission_logs(
                per_log_id serial primary key,
                target_schema_name varchar(100),
                target_schema_owner varchar(100),
                target_object_name varchar(1000),
                role_name varchar(100),
                role_privileges varchar(100),
                status varchar(100),
                created_by varchar(100) DEFAULT CURRENT_USER,
                created_date timestamp DEFAULT now()
			);  
            raise notice 'created table  ';
        end if;
    end;
    begin
    	select json_agg(rjhs_role_map) into res from rjhs_grants.rjhs_role_map  where is_active='Y';
		raise notice 'res value =  %',res;
        for t in select * from json_array_elements(res)
        loop
			raise notice 'all data = %',t;
			target_schema := t->>'target_schema';
            target_owner := t->>'target_schema_owner';
            is_write := t->>'is_write_allowed';
            is_read := t->>'is_read_allowed';
            role_name := t->>'role_name';
			
            insert into rjhs_grants.permission_logs(target_schema_name, target_schema_owner, target_object_name, role_name, role_privileges, status, created_by)
			values (target_schema, target_owner, target_schema,role_name,'*' , 'process start',login_user);
            raise notice 'tables target_schema %', target_schema;
           
            if is_read = 'true' then
                execute 'revoke all on schema public from public'; 
                execute 'grant usage on schema public to public';
                raise notice 'revoke all on schema public from public';
                insert into rjhs_grants.permission_logs(target_schema_name, target_schema_owner, target_object_name, role_name, role_privileges, status, created_by)
				values (target_schema, target_owner, target_schema,role_name,'*' , 'revoke all',login_user);
            end if;
			
            execute 'grant usage on schema ' || target_schema ||' to ' || role_name;
            
			insert into rjhs_grants.permission_logs(target_schema_name, target_schema_owner, target_object_name, role_name, role_privileges, status, created_by)
			values (target_schema, target_owner, target_schema,role_name,'*' , 'grant usage on schema',login_user);
            
			select array_agg(tablename) into tname from pg_catalog.pg_tables where tableowner=target_owner and schemaname=target_schema; 
            
			raise notice 'tables %', tname;
			length:=array_length(tname,1);
			
			if length > 0 then
                foreach tblname in array tname
                loop 
                     if  is_write = 'true' then
                        raise notice 'Permission on schema write %', target_schema;
                        execute  'grant all on table ' ||  target_schema || '.'|| tblname || ' to ' || role_name;
                        raise notice 'Permission on table write %',tblname;
                        insert into rjhs_grants.permission_logs(target_schema_name, target_schema_owner, target_object_name, role_name, role_privileges, status, created_by)
						values (target_schema, target_owner, tblname,role_name,'ALL' , 'pass',login_user);
                    else
                        raise notice 'Permission on schema read %', target_schema;
                        execute 'grant select on table ' ||  target_schema || '.'|| tblname || ' to ' || role_name;
                    	raise notice 'Permission on table read %',tblname;
                        insert into rjhs_grants.permission_logs(target_schema_name, target_schema_owner, target_object_name, role_name, role_privileges, status, created_by)
						values (target_schema, target_owner, tblname,role_name,'SELCET' , 'pass',login_user);
                    end if;
                end loop;
            end if;
			
			--permission for sequences 
			select array_agg(s.sequence_name::text) into seqname from information_schema.sequences s join pg_catalog.pg_class c on (s.sequence_name=c.relname) 
			join pg_catalog.pg_user u on(c.relowner=u.usesysid) where s.sequence_schema=target_schema and u.usename=target_owner;
			
			if array_length(seqname,1) > 0 then
				foreach sqname in array seqname
					loop
						if is_write='true' then
							raise notice 'Permission on schema(for seq) write %', target_schema;
							execute  'grant all on sequence ' ||  target_schema || '.'|| sqname || ' to ' || role_name;
							raise notice 'Permission on sequence write %',sqname;
							insert into rjhs_grants.permission_logs(target_schema_name, target_schema_owner, target_object_name, role_name, role_privileges, status, created_by)
							values (target_schema, target_owner, sqname,role_name,'ALL' , 'pass',login_user);
							
						else
							raise notice 'Permission on schema(for seq) read %', target_schema;
							execute  'grant select on sequence ' ||  target_schema || '.'|| sqname || ' to ' || role_name;
							raise notice 'Permission on sequence read %',sqname;
							insert into rjhs_grants.permission_logs(target_schema_name, target_schema_owner, target_object_name, role_name, role_privileges, status, created_by)
							values (target_schema, target_owner, sqname,role_name,'SELECT' , 'pass',login_user);
						end if;
					end loop;		
				end if;	

			-- access to user_defined functions
			select array_agg(proname||'('||pg_catalog.pg_get_function_identity_arguments(p.oid)||')') into funname  from pg_catalog.pg_namespace n 
			join pg_catalog.pg_proc p on pronamespace = n.oid 
			join  pg_catalog.pg_user u on(p.proowner=u.usesysid)
			where nspname = target_schema and u.usename=target_owner; 
				
			if array_length(funname,1)>0 then
				foreach fname in array funname
					loop
						if is_write='true' then
							raise notice 'Permission on schema(for function) write %', target_schema;
							execute  'grant all on function ' ||  target_schema || '.'|| fname || 'to ' || role_name;
							raise notice 'Permission on function write %',fname;
							insert into rjhs_grants.permission_logs(target_schema_name, target_schema_owner, target_object_name, role_name, role_privileges, status, created_by)
							values (target_schema, target_owner, fname,role_name,'ALL' , 'pass',login_user);
							
						else
							raise notice 'Permission on schema(for function) read %', target_schema;
							execute  'grant execute on function ' ||  target_schema || '.'|| fname || 'to ' || role_name;
							raise notice 'Permission on function read %',fname;
							insert into rjhs_grants.permission_logs(target_schema_name, target_schema_owner, target_object_name, role_name, role_privileges, status, created_by)
							values (target_schema, target_owner, fname,role_name,'SELECT' , 'pass',login_user);
						end if; 
					end loop;
			end if;	
			
            insert into rjhs_grants.permission_logs(target_schema_name, target_schema_owner, target_object_name, role_name, role_privileges, status, created_by)
			values (target_schema, target_owner, target_schema,role_name,'*' , 'process end',login_user);
        end loop;
    end;
return 1;
end;
$status$
language plpgsql;





