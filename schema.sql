create table oauth_access_token (
	authentication_id VARCHAR(255) NOT NULL,
  token_id VARCHAR(255),
  token BLOB,
  user_name VARCHAR(255),
  client_id VARCHAR(255),
  authentication BLOB,
  refresh_token VARCHAR(255),
	PRIMARY KEY (authentication_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

create table oauth_refresh_token (
  token_id VARCHAR(255),
  token BLOB,
  authentication BLOB
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

create table oauth_client_details (
  client_id VARCHAR(255) NOT NULL,
  resource_ids VARCHAR(255),
  client_secret VARCHAR(255),
  scope VARCHAR(255),
  authorized_grant_types VARCHAR(255),
  web_server_redirect_uri VARCHAR(255),
  authorities VARCHAR(255),
  access_token_validity INT,
  refresh_token_validity INT,
  additional_information VARCHAR(4096),
  autoapprove VARCHAR(255),
	PRIMARY KEY (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

insert into oauth_client_details
(client_id, resource_ids, client_secret, scope, authorized_grant_types,web_server_redirect_uri,authorities, access_token_validity,refresh_token_validity, additional_information)
values
('client_id','resource_id', '$2a$10$LFo4DsCxmJzcVbUyzcNU6elgSrekeIR0RCr6lS8rGvFr6tH6nn3f.', 'all','client_credentials,password,refresh_token','http://localhost:8000/','admin',null,null,null);


