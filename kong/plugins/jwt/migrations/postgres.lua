local plugin_config_iterator = require("kong.dao.migrations.helpers").plugin_config_iterator

return {
  {
    name = "2015-06-09-jwt-auth",
    up = [[
      CREATE TABLE IF NOT EXISTS jwt_secrets(
        id uuid,
        consumer_id uuid REFERENCES consumers (id) ON DELETE CASCADE,
        key text UNIQUE,
        secret text UNIQUE,
        created_at timestamp without time zone default (CURRENT_TIMESTAMP(0) at time zone 'utc'),
        PRIMARY KEY (id)
      );

      DO $$
      BEGIN
        IF (SELECT to_regclass('jwt_secrets_key')) IS NULL THEN
          CREATE INDEX jwt_secrets_key ON jwt_secrets(key);
        END IF;
        IF (SELECT to_regclass('jwt_secrets_secret')) IS NULL THEN
          CREATE INDEX jwt_secrets_secret ON jwt_secrets(secret);
        END IF;
        IF (SELECT to_regclass('jwt_secrets_consumer_id')) IS NULL THEN
          CREATE INDEX jwt_secrets_consumer_id ON jwt_secrets(consumer_id);
        END IF;
      END$$;
    ]],
    down = [[
      DROP TABLE jwt_secrets;
    ]]
  },
  {
    name = "2016-03-07-jwt-alg",
    up = [[
      ALTER TABLE jwt_secrets ADD COLUMN algorithm text;
      ALTER TABLE jwt_secrets ADD COLUMN rsa_public_key text;
    ]],
    down = [[
      ALTER TABLE jwt_secrets DROP COLUMN algorithm;
      ALTER TABLE jwt_secrets DROP COLUMN rsa_public_key;
    ]]
  },
  {
    name = "2017-05-22-jwt_secret_not_unique",
    up = [[
      ALTER TABLE jwt_secrets DROP CONSTRAINT IF EXISTS jwt_secrets_secret_key;
    ]],
    down = [[
      ALTER TABLE jwt_secrets ADD CONSTRAINT jwt_secrets_secret_key UNIQUE(secret);
    ]],
  },
  {
    name = "2017-07-31-120200_jwt-auth_preflight_default",
    up = function(_, _, dao)
      for ok, config, update in plugin_config_iterator(dao, "jwt") do
        if not ok then
          return config
        end
        if config.run_on_preflight == nil then
          config.run_on_preflight = true
          local _, err = update(config)
          if err then
            return err
          end
        end
      end
    end,
    down = function(_, _, dao) end  -- not implemented
  },
  {
    name = "2018-05-24-184000_jwt_uri_whitelist_default",
    up = function(_, _, dao)
      for ok, config, update in plugin_config_iterator(dao, "jwt") do
        if not ok then
          return config
        end
        if config.uri_whitelist == nil then
          config.uri_whitelist = {}
          local _, err = update(config)
          if err then
            return err
          end
        end
      end
    end,
    down = function(_, _, dao) end  -- not implemented
  },
  {
    name = "2018-05-24-184000_jwt_ip_whitelist_default",
    up = function(_, _, dao)
      for ok, config, update in plugin_config_iterator(dao, "jwt") do
        if not ok then
          return config
        end
        if config.ip_whitelist == nil then
          config.ip_whitelist = {}
          local _, err = update(config)
          if err then
            return err
          end
        end
      end
    end,
    down = function(_, _, dao) end  -- not implemented
  },
  {
    name = "2018-05-24-184000_jwt_app_key_auth_default",
    up = function(_, _, dao)
      for ok, config, update in plugin_config_iterator(dao, "jwt") do
        if not ok then
          return config
        end
        if config.app_key_auth == nil then
          config.app_key_auth = {}
          local _, err = update(config)
          if err then
            return err
          end
        end
      end
    end,
    down = function(_, _, dao) end  -- not implemented
  },
  {
    name = "2018-03-15-150000_jwt_maximum_expiration",
    up = function(_, _, dao)
      for ok, config, update in plugin_config_iterator(dao, "jwt") do
        if not ok then
          return config
        end
        if config.maximum_expiration == nil then
          config.maximum_expiration = 0
          local _, err = update(config)
          if err then
            return err
          end
        end
      end
    end,
    down = function(_, _, dao) end  -- not implemented
  },
  {
    name = "2019-01-02-134000_jwt_uri_whitelist_with_jwt_default",
    up = function(_, _, dao)
      for ok, config, update in plugin_config_iterator(dao, "jwt") do
        if not ok then
          return config
        end
        if config.uri_whitelist_with_jwt == nil then
          config.uri_whitelist_with_jwt = {}
          local _, err = update(config)
          if err then
            return err
          end
        end
      end
    end,
    down = function(_, _, dao) end  -- not implemented
  },
}
