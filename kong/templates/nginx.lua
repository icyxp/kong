return [[
> if nginx_user then
user ${{NGINX_USER}};
> end
worker_processes ${{NGINX_WORKER_PROCESSES}};
daemon ${{NGINX_DAEMON}};

pid pids/nginx.pid;
error_log ${{PROXY_ERROR_LOG}} ${{LOG_LEVEL}};

> if nginx_optimizations then
worker_rlimit_nofile ${{WORKER_RLIMIT}};
> end

events {
> if nginx_optimizations then
    worker_connections ${{WORKER_CONNECTIONS}};
    multi_accept on;
> end
}

http {

    log_format scribe '{"access_time":"$time_iso8601", "remote_addr":"$remote_addr", "x_forwarded_for":"$http_x_forwarded_for", "status":"$status", "upstream_addr":"$upstream_addr", "upstream_status":"$upstream_status", "upstream_response_time":"$upstream_response_time", "request_method":"$request_method", "request_scheme":"$http_x_forwarded_proto", "request_uri":"$request_uri", "body_bytes_sent":"$body_bytes_sent", "bytes_sent":"$bytes_sent", "request_time":"$request_time", "host_addr":"$host", "api_version":"$http_x_api_version", "jwt":"$http_authorization", "correlation_id":"$http_x_correlation_id", "client_id":"$http_x_client_id", "http_refer":"$http_referer", "http_user_agent":"$http_user_agent", "x_patsnap_from":"$http_x_patsnap_from"}';
    
    include 'nginx-kong.conf';
}
]]
